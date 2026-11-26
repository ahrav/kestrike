//! A repeated READY of the active session changes nothing.
//!
//! The scenario runs the real owner scene of `net::put_tests` (an owner over a simulated disk and two
//! clients on simulated links). Client 0 opens a fresh session, and the owner's READY is copied in
//! flight with `Net::peek`. Once that session is active the client admits a GET under it and calls
//! `Client::session` to open another session, which leaves a HELLO pending. A byte-identical copy of
//! the active session's READY is then queued toward the client with `Net::inject`, and the client is
//! polled once. The poll that takes the copy must leave the client as a poll without the copy leaves
//! it: still `Opening`, the pending HELLO and the GET's frame both sent, nothing counted as dropped,
//! and the active session's epoch unchanged.
//!
//! From there every HELLO is taken off the link before the owner sees it, so the opening stays under
//! way. The GET admitted before the copy completes with the published bytes under the active session,
//! the HELLO goes out again one `bootstrap_retry_us` after the first, and the client is still
//! `Opening` with the same active epoch.
//!
//! The control runs the same steps without the copy and must see the same things, apart from the one
//! datagram the copy's poll receives.
//!
//! Premises are judged apart from the property: the copied datagram is a READY that names the active
//! session's epoch, the fresh session replaced the scene's first one, and no datagram was in flight
//! toward the owner before the copy's poll.
//!
//! Each test gathers what it saw into plain values inside the scene, lets the scene go, and asserts
//! last, so a failure ends in the test's own result line.

use super::client::SessionState;
use super::fetch::Outcome;
use super::frame::{Kind, parse};
use super::owner_tests::{client_config, key, payload};
use super::put_tests::scene;
use crate::sim::round::Actor;
use crate::storage::Crc32c;

/// Turns a step that must happen may take before the scenario gives up on it.
const PATIENCE: u64 = 2_000;

/// The kind and session epoch a datagram's header names, when its bytes parse.
fn named(bytes: &[u8]) -> Option<(Kind, u64)> {
    let frame = parse(Crc32c::detect(), bytes, false).ok()?;
    let header = frame.header();
    Some((header.kind, header.epoch))
}

/// What the premises need: how the scenario reached the poll that takes the copy.
#[derive(Debug, PartialEq, Eq)]
struct Premise {
    /// The client's state once the fresh session opened.
    opened: SessionState,
    /// Whether the fresh session's epoch differs from the scene's first session's.
    fresh_epoch: bool,
    /// Whether the datagram copied in flight is a READY naming the active session's epoch.
    copy_is_active_ready: bool,
    /// Datagrams in flight toward the owner before the copy's poll.
    in_flight_before: usize,
    /// The client's state after `Client::session`, before the copy's poll.
    asked: SessionState,
}

/// What the poll that takes the copy, and the turns after it, left.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// Datagrams the copy's poll received.
    received: u32,
    /// Datagrams the copy's poll counted as dropped.
    dropped: u32,
    /// Whether the frames the copy's poll sent are exactly one GET and one HELLO.
    sent_get_and_hello: bool,
    /// The client's state after the copy's poll.
    state: SessionState,
    /// Bootstrap frames sent since `Client::session`, after the copy's poll.
    bootstrap_sent: u64,
    /// Whether the active session's epoch after the copy's poll is the one before it.
    epoch_kept: bool,
    /// The GET admitted before the copy: its outcome and whether its bytes are the published ones.
    get: (Option<Outcome>, bool),
    /// Microseconds from the first HELLO to the second, when a second one left.
    resent_after_us: Option<u64>,
    /// The client's state and whether its active epoch is still the same once the GET ended.
    end: (SessionState, bool),
}

/// Runs the scenario, delivering the copy of the active session's READY when `replay`.
fn run(replay: bool) -> (Premise, Seen) {
    let mut result = None;
    scene(&[], |mut scene| {
        let first_epoch = scene.clients[0].session_epoch();
        // A fresh session, whose READY is copied in flight right after the owner's poll sends it.
        scene.clients[0].session(scene.turn * 100);
        let mut ready: Option<Vec<u8>> = None;
        let mut turns = 0;
        while scene.clients[0].state() != SessionState::Active && turns < PATIENCE {
            scene.turn_then(
                &mut [(Actor::Client(0), &mut |clients, _, now| {
                    let _ = clients[0].poll(now);
                })],
                &mut |_, nets| {
                    let newest = nets[0].borrow().peek(0);
                    if let Some(bytes) = newest
                        .filter(|bytes| named(bytes).is_some_and(|(kind, _)| kind == Kind::Ready))
                    {
                        ready = Some(bytes);
                    }
                },
            );
            turns += 1;
        }
        let opened = scene.clients[0].state();
        let active_epoch = scene.clients[0].session_epoch();
        let copy_is_active_ready = match (&ready, active_epoch) {
            (Some(bytes), Some(epoch)) => named(bytes) == Some((Kind::Ready, epoch)),
            _ => false,
        };
        // Whatever the opening left in flight lands before the GET is admitted.
        for _ in 0..8 {
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })]);
        }
        let now = scene.turn * 100;
        let in_flight_before = scene.nets[0].borrow().pending(1);
        let get = scene.clients[0].get(key(1), 0, 1 << 20, now, 30_000_000);
        scene.clients[0].session(now);
        let asked = scene.clients[0].state();
        if let (true, Some(bytes)) = (replay, &ready) {
            scene.nets[0].borrow_mut().inject(0, bytes);
        }
        // The poll that takes the copy.
        let report = scene.clients[0].poll(now);
        let state = scene.clients[0].state();
        let bootstrap_sent = scene.clients[0].bootstrap_sent();
        let epoch_kept = active_epoch.is_some() && scene.clients[0].session_epoch() == active_epoch;
        // The frames that poll sent. Every HELLO is taken off the link here and below, so the owner
        // never answers the opening.
        let mut sent = Vec::new();
        let mut hellos = Vec::new();
        scene.nets[0].borrow_mut().retain(1, |bytes| {
            let kind = named(bytes).map(|(kind, _)| kind);
            sent.push(kind);
            if kind == Some(Kind::Hello) {
                hellos.push(now);
            }
            kind != Some(Kind::Hello)
        });
        let sent_get_and_hello = sent.len() == 2
            && report.sent == 2
            && sent.contains(&Some(Kind::Get))
            && sent.contains(&Some(Kind::Hello));
        // The GET runs to its end under the active session while the opening waits for an answer.
        let mut bytes = Vec::new();
        let mut outcome = None;
        let mut turns = 0;
        while let (Ok(id), true) = (get, turns < PATIENCE) {
            if outcome.is_some() && hellos.len() >= 2 {
                break;
            }
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
                let _ = clients[0].poll(now);
                while let Some(fragment) = clients[0].take(id) {
                    bytes.extend_from_slice(fragment.bytes());
                }
                nets[0].borrow_mut().retain(1, |bytes| {
                    let hello = named(bytes).is_some_and(|(kind, _)| kind == Kind::Hello);
                    if hello {
                        hellos.push(now);
                    }
                    !hello
                });
            })]);
            outcome = outcome.or(scene.clients[0].outcome(id));
            turns += 1;
        }
        let end = (
            scene.clients[0].state(),
            active_epoch.is_some() && scene.clients[0].session_epoch() == active_epoch,
        );
        result = Some((
            Premise {
                opened,
                fresh_epoch: active_epoch.is_some() && active_epoch != first_epoch,
                copy_is_active_ready,
                in_flight_before,
                asked,
            },
            Seen {
                received: report.received,
                dropped: report.dropped,
                sent_get_and_hello,
                state,
                bootstrap_sent,
                epoch_kept,
                get: (outcome, bytes == payload(1000, 1)),
                resent_after_us: (hellos.len() >= 2).then(|| hellos[1] - hellos[0]),
                end,
            },
        ));
    });
    result.expect("the scene ran its body")
}

/// What the property says a poll leaves, whether or not it took the copy.
fn unchanged(received: u32) -> Seen {
    Seen {
        received,
        dropped: 0,
        sent_get_and_hello: true,
        state: SessionState::Opening,
        bootstrap_sent: 1,
        epoch_kept: true,
        get: (Some(Outcome::Complete), true),
        resent_after_us: Some(client_config(0).bootstrap_retry_us),
        end: (SessionState::Opening, true),
    }
}

fn premise() -> Premise {
    Premise {
        opened: SessionState::Active,
        fresh_epoch: true,
        copy_is_active_ready: true,
        in_flight_before: 0,
        asked: SessionState::Opening,
    }
}

#[test]
fn a_copy_of_the_active_sessions_ready_leaves_the_opening_the_get_and_the_session_as_they_were() {
    let (reached, seen) = run(true);
    assert_eq!(
        reached,
        premise(),
        "premise: the copy's poll was not reached as scripted"
    );
    assert_eq!(
        seen,
        unchanged(1),
        "a repeated READY of the active session changed the client"
    );
}

#[test]
fn the_same_steps_without_the_copy_leave_the_same_state() {
    let (reached, seen) = run(false);
    assert_eq!(
        reached,
        premise(),
        "premise: the poll was not reached as scripted"
    );
    assert_eq!(seen, unchanged(0));
}
