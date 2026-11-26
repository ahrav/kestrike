//! Session derivation over the simulated store: the old medium rule reissues a generation under a stale lowered
//! slot while the store-derived session never repeats; every unknown outcome of the `E` bump refuses without a
//! re-read licensing the attempt.

use std::cell::Cell;

use super::layout::{Slot, first_slot};
use super::root::{Decision, Probed, Root, decide};
use super::session::{Session, SessionRefusal, candidate};
use crate::failover::records::ShardRecord;
use crate::net::ownership::ShardGeneration;
use crate::storage::store::sim::Shared;
use crate::storage::store::{Bumped, Key, StoreError};
use crate::storage::store_tests::{OWNER, UNKNOWN, attempt, client, reread_and_proceed, shard};

/// A store holding the shard record at generation `generation` with `E = attempts`.
fn store_at(generation: u64, attempts: u32) -> Shared {
    let store = Shared::new();
    let record = ShardRecord {
        generation: ShardGeneration::new(generation).unwrap(),
        attempts,
        ..crate::storage::store_tests::record()
    };
    client(&store).create_shard(record).unwrap();
    store
}

fn bump(store: &Shared) -> Result<Bumped, StoreError> {
    attempt(&mut client(store), OWNER)
}

/// The session of the acknowledged bump `E: attempts -> attempts + 1` at `generation`.
pub(crate) fn session_at(generation: u64, attempts: u32) -> Session {
    Session::activate(bump(&store_at(generation, attempts)).unwrap()).unwrap()
}

/// A fresh session at generation 1 for each call on the calling thread, each above every earlier one since the
/// sequence last restarted: the first is `2^32 + 2`, so an attach that follows another on the same medium writes a
/// higher session.
pub(crate) fn next_session() -> Session {
    DRAWN.set(DRAWN.get() + 1);
    session_at(1, NEXT.replace(NEXT.get() + 1))
}

/// The encoded session the calling thread's next [`next_session`] returns.
pub(crate) fn upcoming_session() -> u64 {
    session_at(1, NEXT.get()).get()
}

thread_local! {
    static NEXT: Cell<u32> = const { Cell::new(0) };
    static DRAWN: Cell<u64> = const { Cell::new(0) };
}

impl Session {
    /// The number of sessions the calling thread has drawn through [`next_session`].
    pub(crate) fn fixture_draws() -> u64 {
        DRAWN.get()
    }

    /// For generation 1, this session's committed attempt count sets a lower bound on the calling thread's
    /// [`next_session`] position; other generations leave the position unchanged.
    pub(crate) fn continue_fixture_sequence(&self) {
        if self.generation().get() == 1 {
            NEXT.set(NEXT.get().max(self.target().attempts));
        }
    }
}

/// Restarts the calling thread's [`next_session`] sequence at `2^32 + 2`. When the returned guard drops, on return
/// or unwind, the sequence continues above both its position before the restart and every session drawn since.
#[must_use = "the sequence continues above its earlier position once the guard drops"]
pub(crate) fn restart_sessions() -> Restarted {
    Restarted(NEXT.replace(0), std::marker::PhantomData)
}

/// The [`next_session`] position before a [`restart_sessions`], on the thread that restarted it: the raw-pointer
/// marker keeps the guard on that thread, so its drop sets that thread's sequence.
pub(crate) struct Restarted(u32, std::marker::PhantomData<*const ()>);

impl Drop for Restarted {
    fn drop(&mut self) {
        NEXT.set(NEXT.get().max(self.0));
    }
}

/// The medium rule the session replaces, kept as the control: one above the higher valid root generation.
fn medium_rule(a: Option<u64>, b: Option<u64>) -> u64 {
    a.max(b).map_or(1, |highest| highest + 1)
}

/// Whether successive attaches wrote strictly increasing values, which NO-REISSUE requires.
fn strictly_increase(issued: &[u64]) -> bool {
    issued.windows(2).all(|pair| pair[0] < pair[1])
}

fn probe(generation: u64) -> Probed {
    let root = Root::reset(
        generation,
        crate::storage::TEST_CLOCK.encode(),
        crate::storage::TEST_FEED.encode(),
    );
    Some(Ok((super::FormatId([7; 16]), root)))
}

/// Identical probe readings make the medium rule issue one generation twice; two acknowledged bumps of one shard
/// record give two sessions.
#[test]
fn identical_probes_issue_one_generation() {
    for (a, b, issued) in [
        (None, None, 1),
        (Some(5), None, 6),
        (None, Some(5), 6),
        (Some(5), Some(4), 6),
    ] {
        let old = [medium_rule(a, b), medium_rule(a, b)];
        assert_eq!(old, [issued; 2], "{a:?} {b:?}");
        assert!(
            !strictly_increase(&old),
            "{a:?} {b:?}: the medium rule reissues"
        );
    }
    let store = store_at(3, 0);
    let first = Session::activate(bump(&store).unwrap()).unwrap();
    let second = Session::activate(bump(&store).unwrap()).unwrap();
    let new = [first.get(), second.get()];
    assert_eq!(new, [(3 << 32) | 2, (3 << 32) | 4]);
    assert!(strictly_increase(&new));
}

/// Three attaches over slots holding 5 in A and 4 in B. Each attach reads both slots, and `issue` gives the value it
/// writes and the slot its first RESET copy goes to; the attach crashes before its second copy, and a stale
/// generation-4 write then lands on the slot the first copy reached, so the next attach reads 5 and 4 again.
/// Returns the value each attach wrote.
fn crash_and_lower(mut issue: impl FnMut(u64, u64) -> (u64, Slot)) -> Vec<u64> {
    let mut slots = (5, 4);
    let mut written = Vec::new();
    for _ in 0..3 {
        let (value, first) = issue(slots.0, slots.1);
        written.push(value);
        match first {
            Slot::A => slots.0 = 4,
            Slot::B => slots.1 = 4,
        }
    }
    written
}

/// A stale attempt overwrites the higher root slot with a lower generation. The control applying the medium rule
/// reissues the generation the crashed attach wrote; the store-derived sessions of the same attaches never repeat,
/// and each RESET decision over the lowered slot writes the new session.
#[test]
fn stale_slot_lowering_never_reissues() {
    let old = crash_and_lower(|a, b| {
        (
            medium_rule(Some(a), Some(b)),
            first_slot(Some((a, 0)), Some((b, 0))),
        )
    });
    assert_eq!(old, [6, 6, 6]);
    assert!(!strictly_increase(&old), "the medium rule reissues 6");

    let store = store_at(1, 0);
    let new = crash_and_lower(|a, b| {
        let session = Session::activate(bump(&store).unwrap()).unwrap();
        let expected = session.get();
        let Decision::Reset { session, first, .. } = decide(&probe(a), &probe(b), &session) else {
            panic!("the lowered slot holds no root at or above the session");
        };
        assert_eq!(session, expected, "the RESET writes the attach's session");
        (session, first)
    });
    assert_eq!(new, [(1 << 32) | 2, (1 << 32) | 4, (1 << 32) | 6]);
    assert!(strictly_increase(&new));
}

/// A timeout or failure of the `E` bump, in the arm that commits and the one that does not, leaves the attempt
/// without a witness, so it has no session. A second attempt's own acknowledged bump yields its session; the
/// control that re-reads the shard record and takes the attempt it shows consumed shares that session.
#[test]
fn unknown_outcome_refuses_without_reread() {
    for arm in UNKNOWN {
        let store = store_at(2, 0);
        let mut first = client(&store);
        let read = first.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        store.schedule(arm);
        assert_eq!(
            first.bump(&read).map(|_| ()),
            Err(StoreError::Unknown),
            "{arm:?}"
        );
        let second = Session::activate(bump(&store).unwrap()).unwrap();
        let (generation, consumed) = reread_and_proceed(&mut first).unwrap();
        let control = (u64::from(generation.get() as u32) << 32) | u64::from(2 * consumed + 2);
        assert_eq!(
            control,
            second.get(),
            "{arm:?}: the re-read control shares the second attempt's session"
        );
    }
}

/// An attempt whose activated epoch would pass `ActivatedEpoch::MAX` refuses, as does `g = 2^32 - 1`; the last
/// admitted attempt activates `a = 2^32 - 4`, and every candidate epoch is odd.
#[test]
fn exhaustion_refuses_and_epochs_keep_their_parity() {
    let last = crate::failover::records::ATTEMPTS_MAX - 1;
    let session = session_at(5, last);
    assert_eq!(
        session.epoch().get(),
        crate::net::ownership::ActivatedEpoch::MAX
    );
    assert_eq!(
        session.get(),
        (5 << 32) | u64::from(crate::net::ownership::ActivatedEpoch::MAX)
    );
    let highest = session_at(u64::from(u32::MAX) - 1, 0);
    assert_eq!(highest.generation().get(), u64::from(u32::MAX) - 1);
    assert_eq!(highest.get(), (u64::from(u32::MAX - 1) << 32) | 2);
    let exhausted = bump(&store_at(u64::from(u32::MAX), 0)).unwrap();
    assert_eq!(
        Session::activate(exhausted),
        Err(SessionRefusal::GenerationExhausted)
    );
    assert_eq!(
        bump(&store_at(5, last + 1)).map(|_| ()),
        Err(StoreError::AttemptsExhausted)
    );
    for n in [0, 1, 7, last] {
        assert_eq!(candidate(n).unwrap() % 2, 1);
        assert_eq!(candidate(n).unwrap() + 1, session_at(1, n).epoch().get());
    }
}

/// The restart guard keeps sessions increasing across normal return and unwind: the draw after a guard exceeds
/// every session drawn before it and inside its scope.
#[test]
fn a_restart_guard_continues_the_sequence_above_every_earlier_draw() {
    let before = next_session().get();
    drop(restart_sessions());
    assert_eq!(next_session().get(), before + 2, "a body with no draw");

    let before = next_session().get();
    let inner = {
        let _restarted = restart_sessions();
        (0..4).map(|_| next_session().get()).max().unwrap()
    };
    let after = next_session().get();
    assert!(after > inner && after > before, "{before} {inner} {after}");

    let before = next_session().get();
    let unwound = std::panic::catch_unwind(|| {
        let _restarted = restart_sessions();
        panic!("the body unwinds");
    });
    assert!(unwound.is_err());
    assert_eq!(
        next_session().get(),
        before + 2,
        "an unwound body with no draw"
    );
}

/// A compare-and-swap of `E` whose outcome is unknown, from a timeout that committed and one that did not,
/// yields no witness, so the attempt activates no epoch; the next attempt's own acknowledged bump activates
/// the epoch of the `n` it read, which is the void attempt's `n` exactly when that timeout did not commit.
#[test]
fn cas_timeout_refuses_both_arms() {
    for commit in [true, false] {
        let store = crate::storage::store_tests::seeded();
        let mut first = client(&store);
        let read = first.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        store.schedule(crate::storage::store::sim::Arm::Timeout { commit });
        assert_eq!(
            first.bump(&read).map(|_| ()),
            Err(StoreError::Unknown),
            "commit {commit}"
        );
        let mut next = client(&store);
        let read = next.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let session = Session::activate(next.bump(&read).unwrap()).unwrap();
        let void = u32::from(commit);
        assert_eq!(session.epoch().get(), 2 * void + 2, "commit {commit}");
    }
}

/// A takeover's acknowledged compare-and-swap activates the successor's session `(g, 2E + 2)` naming the successor as
/// owner, and a restart bump over the same read activates nothing: the store-derived sessions of one shard record
/// stay distinct across the two writes that consume an attempt.
#[test]
fn a_takeover_witness_activates_the_successors_session_once() {
    use crate::storage::store_tests::SPARE;
    let store = Shared::new();
    let standby = crate::failover::records::Host::new(SPARE).unwrap();
    let record = ShardRecord {
        generation: ShardGeneration::new(3).unwrap(),
        attempts: 4,
        standby: Some(standby),
        ..crate::storage::store_tests::record()
    };
    client(&store).create_shard(record).unwrap();
    let mut owner = client(&store);
    let read = owner.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let mut successor = client(&store);
    let taken = successor
        .take_over(
            &read,
            crate::failover::retire::Target::of(read.value()),
            standby,
        )
        .unwrap();
    let session = Session::activate(taken).unwrap();
    assert_eq!(session.get(), (3 << 32) | 10);
    assert_eq!(
        session.target().owner,
        crate::failover::records::Host::new(SPARE).unwrap()
    );
    assert_eq!(
        owner.bump(&read).map(drop),
        Err(StoreError::Refused(
            crate::storage::store::Refusal::Condition
        ))
    );
    let next = bump(&store).unwrap_err();
    assert_eq!(
        next,
        StoreError::Refused(crate::storage::store::Refusal::Condition)
    );
    let mut rereader = client(&store);
    let current = rereader.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    let successor_session = Session::activate(rereader.bump(&current).unwrap()).unwrap();
    assert!(successor_session.get() > session.get());
    assert_eq!(successor_session.get(), (3 << 32) | 12);
}
