//! The worker contains at most once, and an expired worker refuses every
//! later arm. An expiry leaves the stalled call in place, and the supervisor
//! contains once. The episode begins no further stage, loses the link and
//! reconciles nothing, so every buffer the device may hold stays held.
//! `into_port` then hands the port back without stopping it to settle a
//! quarantine.
//!
//! The first three tests ask the watch itself, because a burst whose episode
//! expired has lost its link and starts no later recovery: once a deadline
//! expired and its disarm reported the expiry, each later `arm` returns
//! `false`, `expired` stays `true`, and the supervisor was asked to contain
//! once. The last two run a burst over the mock port with a quarantined
//! chain: after an expiry inside the stop stage, a later turn begins no stage
//! and `into_port` stops nothing and returns no header buffer; with the same
//! steps and no expiry, `into_port` stops the port and the chain's header
//! buffer returns.
//!
//! Each test records what it saw in plain values, ends its fixture, and
//! asserts last.

use std::sync::Arc;
use std::time::Duration;

use super::burst::{Burst, Link};
use super::burst_tests::{Containment, LOCAL, PEERS, RECOVERY_DEADLINE, StallClock, watch_on};
use super::mempool::Role;
use super::mock::{self, Forged, MockPort, iova};
use super::recovery::{RecoveryEpisode, RecoveryStage, RecoveryWatch};
use super::watchdog::Supervisor;
use super::wire::Wire;
use crate::net::{Datagrams, Outgoing, Payload, PeerId};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{BufferArena, EngineBudget, PoolKind};

/// The arms a test makes after the disarm that reported the expiry.
const LATER_ARMS: usize = 3;

/// What one later episode saw of an expired watch: the arm's answer, then
/// `expired`, then the answer of the disarm that follows the arm.
type Later = (bool, bool, bool);

/// What a refused later episode sees: the arm is refused, the watch stays
/// expired, and the disarm answers that the watch asked to contain.
const REFUSED: Later = (false, true, true);

/// What a test saw of one watch, read before the watch was dropped.
#[derive(Debug, PartialEq)]
struct Seen {
    /// The answer of the arm whose deadline then expired.
    armed: bool,
    /// `expired` after that arm and before the deadline passed, where the
    /// test controls the clock.
    expired_before: Option<bool>,
    /// `expired` once the supervisor was asked to contain.
    expired_after: bool,
    /// The answer of the disarm that follows the expiry.
    disarm: bool,
    /// Each later episode, in order.
    later: Vec<Later>,
    /// The containments the supervisor was asked for, counted after the
    /// watch was dropped, which joins its worker.
    contained: u32,
}

/// Arms `watch` again `LATER_ARMS` times, each arm following a disarm, and
/// returns what each of those episodes saw.
fn later_episodes(watch: &mut RecoveryWatch) -> Vec<Later> {
    (0..LATER_ARMS)
        .map(|_| (watch.arm(), watch.expired(), watch.disarm()))
        .collect()
}

/// The watch on the test's clock: one episode arms it, the clock passes the
/// deadline and the worker asks to contain, and the episode's disarm reports
/// the expiry. Every later arm is then refused, the watch stays expired, and
/// the supervisor was asked once.
#[test]
fn an_expired_watch_refuses_every_later_arm_and_contains_once() {
    let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
    let mut watch = watch_on(&clock, &containment);
    let armed = watch.arm();
    let expired_before = Some(watch.expired());
    clock.expire(RECOVERY_DEADLINE);
    containment.wait_requested();
    let expired_after = watch.expired();
    let disarm = watch.disarm();
    let later = later_episodes(&mut watch);
    drop(watch);
    let seen = Seen {
        armed,
        expired_before,
        expired_after,
        disarm,
        later,
        contained: containment.count(),
    };
    assert_eq!(
        seen,
        Seen {
            armed: true,
            expired_before: Some(false),
            expired_after: true,
            disarm: true,
            later: vec![REFUSED; LATER_ARMS],
            contained: 1,
        },
        "after the expiry every later arm is refused and the supervisor was asked once"
    );
}

/// The watch as production starts it, `RecoveryWatch::new` over the
/// monotonic clock, with a deadline of one millisecond that passes in real
/// time. The same holds: every arm after the expiry is refused and the
/// supervisor was asked once.
#[test]
fn an_expired_watch_on_the_monotonic_clock_refuses_every_later_arm() {
    let containment = Arc::new(Containment::default());
    let mut watch = RecoveryWatch::new(
        Duration::from_millis(1),
        Arc::clone(&containment) as Arc<dyn Supervisor>,
    );
    let armed = watch.arm();
    containment.wait_requested();
    let expired_after = watch.expired();
    let disarm = watch.disarm();
    let later = later_episodes(&mut watch);
    drop(watch);
    let seen = Seen {
        armed,
        expired_before: None,
        expired_after,
        disarm,
        later,
        contained: containment.count(),
    };
    assert_eq!(
        seen,
        Seen {
            armed: true,
            expired_before: None,
            expired_after: true,
            disarm: true,
            later: vec![REFUSED; LATER_ARMS],
            contained: 1,
        },
        "after the expiry every later arm is refused and the supervisor was asked once"
    );
}

/// The refusal belongs to the expiry and to nothing earlier. Two episodes
/// arm and disarm before the deadline: each arm is accepted, the watch is
/// not expired and nothing is contained. The third episode's deadline
/// expires, and from then on every arm is refused; across all the episodes
/// the supervisor was asked once.
#[test]
fn a_watch_accepts_each_arm_until_one_deadline_expires_and_none_after() {
    let (clock, containment) = (StallClock::default(), Arc::new(Containment::default()));
    let mut watch = watch_on(&clock, &containment);
    let earlier: Vec<Later> = (0..2)
        .map(|_| (watch.arm(), watch.expired(), watch.disarm()))
        .collect();
    let contained_earlier = containment.count();
    let armed = watch.arm();
    let expired_before = Some(watch.expired());
    clock.expire(RECOVERY_DEADLINE);
    containment.wait_requested();
    let expired_after = watch.expired();
    let disarm = watch.disarm();
    let later = later_episodes(&mut watch);
    drop(watch);
    let seen = Seen {
        armed,
        expired_before,
        expired_after,
        disarm,
        later,
        contained: containment.count(),
    };
    assert_eq!(
        (earlier, contained_earlier),
        (vec![(true, false, false); 2], 0),
        "an episode disarmed before its deadline leaves the watch armable and contains nothing"
    );
    assert_eq!(
        seen,
        Seen {
            armed: true,
            expired_before: Some(false),
            expired_after: true,
            disarm: true,
            later: vec![REFUSED; LATER_ARMS],
            contained: 1,
        },
        "after the expiry every later arm is refused and the supervisor was asked once"
    );
}

/// What a burst's hand-back showed, read from the burst before `into_port`
/// consumed it and from the port and the arena after.
#[derive(Debug, PartialEq)]
struct HandBack {
    /// The uncertain post quarantined its chain.
    quarantined: bool,
    /// The link after the turn that ran the recovery episode.
    link: Link,
    /// The episode that turn recorded.
    episode: RecoveryEpisode,
    /// The stages the port ran in that turn.
    stages: Vec<RecoveryStage>,
    /// The burst's reset count, the port's stages and its call count are the
    /// same after one more turn: the turn began no episode and no stage.
    later_turn_idle: bool,
    /// The quarantine is still pending before the hand-back.
    poisoned: bool,
    /// The burst's counts of quarantined chains it settled as returned and
    /// as released, before the hand-back.
    settled: (u64, u64),
    /// The port's stops before the hand-back and on the port handed back.
    stops: (u32, u32),
    /// The header buffers out of the arena's pool before the hand-back and
    /// after it.
    headers: (u32, u32),
    /// The containments the supervisor was asked for.
    contained: u32,
}

/// The header buffers the burst or the device holds.
fn headers_held(arena: &BufferArena<TestPlatform>) -> u32 {
    let report = arena.report(PoolKind::PacketHeader);
    report.count - report.free
}

/// Runs one burst over the mock port: an uncertain post leaves a chain the
/// device keeps quarantined, one turn runs the recovery episode, a second
/// turn follows, and `into_port` hands the port back. The episode's stop is
/// unproven when `proven` is false. With `expire` the stop stalls until the
/// watchdog expired on the test's clock and asked to contain. The port
/// proves every stop after the episode, so a hand-back that stops it would
/// settle the chain.
fn hand_back(expire: bool, proven: bool) -> HandBack {
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
    let mut burst = Burst::new(
        port,
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        [header.state, payload.state, receive.state],
        Box::leak(Box::new(Forged(translate, recheck))),
        watch_on(&clock, &containment),
        8,
        &mut EngineBudget::unlimited(),
    )
    .unwrap();

    let bytes = [0x53; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &bytes,
        payload: [Payload::Inline(b"q"), Payload::EMPTY],
    };
    burst.port_mut().accept = 0;
    burst.port_mut().uncertain = true;
    let _refused = burst.send(&[datagram]);
    let quarantined = burst.poisoned();

    burst.port_mut().proven_stops = if proven { u32::MAX } else { 0 };
    if expire {
        let (clock, containment) = (clock.clone(), Arc::clone(&containment));
        burst.port_mut().stall = Some((
            RecoveryStage::Stop,
            Box::new(move || {
                clock.expire(RECOVERY_DEADLINE);
                containment.wait_requested();
                true
            }),
        ));
    }
    burst.reclaim();
    let (link, report) = (burst.link(), burst.report());
    let stages = burst.port().stages.clone();
    let calls = burst.port().calls;

    burst.reclaim();
    let later_turn_idle = burst.report().resets == report.resets
        && burst.port().stages == stages
        && burst.port().calls == calls;

    burst.port_mut().proven_stops = u32::MAX;
    let poisoned = burst.poisoned();
    let settled = (
        burst.report().quarantine_returned,
        burst.report().quarantine_released,
    );
    let (stops, headers) = (burst.port().stops, headers_held(arena));
    let port = burst.into_port();
    let seen = HandBack {
        quarantined,
        link,
        episode: report.episode,
        stages,
        later_turn_idle,
        poisoned,
        settled,
        stops: (stops, port.stops),
        headers: (headers, headers_held(arena)),
        contained: containment.count(),
    };
    drop((port, header, payload, receive));
    seen
}

/// An expiry inside the stop stage, whether the stalled stop then proves
/// itself or not: the episode records the stop as the stage begun and the
/// expiry's, the supervisor was asked once, the link is lost and the port ran
/// no stage after the stop. The next turn begins nothing. The quarantine is
/// unreconciled, and `into_port` hands the port back with its stop count
/// unchanged and returns no header buffer. After an unproven stop the
/// chain's one header buffer is still out of its pool. A stalled stop that
/// proves itself had the mock device return that buffer, and the burst
/// still settles nothing.
#[test]
fn into_port_after_an_expired_stop_stops_nothing_and_reconciles_nothing() {
    let seen = [false, true].map(|proven| (proven, hand_back(true, proven)));
    for (proven, seen) in seen {
        let headers = if proven { 0 } else { 1 };
        assert_eq!(
            seen,
            HandBack {
                quarantined: true,
                link: Link::Lost,
                episode: RecoveryEpisode {
                    episode: 1,
                    reached: Some(RecoveryStage::Stop),
                    expired_at: Some(RecoveryStage::Stop),
                    containment_requested: true,
                    containment_verified: false,
                    refused: false,
                },
                stages: vec![RecoveryStage::Stop],
                later_turn_idle: true,
                poisoned: true,
                settled: (0, 0),
                stops: (1, 1),
                headers: (headers, headers),
                contained: 1,
            },
            "a stop that ended proven: {proven}"
        );
    }
}

/// The same steps with no expiry: the episode's stop ends unproven, so the
/// link is lost with the chain still quarantined and nothing contained. Here
/// `into_port` does stop the port to settle the quarantine, the stop is
/// proven, and the chain's header buffer returns to its pool. The hand-back
/// of the test above differs from this one by the expiry alone.
#[test]
fn into_port_after_an_unproven_stop_with_no_expiry_stops_the_port_and_settles_the_chain() {
    assert_eq!(
        hand_back(false, false),
        HandBack {
            quarantined: true,
            link: Link::Lost,
            episode: RecoveryEpisode {
                episode: 1,
                reached: Some(RecoveryStage::Stop),
                ..RecoveryEpisode::default()
            },
            stages: vec![RecoveryStage::Stop],
            later_turn_idle: true,
            poisoned: true,
            settled: (0, 0),
            stops: (1, 2),
            headers: (1, 0),
            contained: 0,
        }
    );
}
