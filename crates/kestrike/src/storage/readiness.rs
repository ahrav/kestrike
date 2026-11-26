//! One atomic word holds recovery readiness in bits 0..3, authority in bits 8..12,
//! and lineage in bits 32..64. Updates preserve the other writer's fields.
//!
//! Invariants owned by this module:
//!
//! - ALLOCATION-READY: fills and builders require `Live` or an unattached volume. Under the pool gate, the check precedes every slot, free-set, extent or ledger write: `Detached` after an attach set the authority field, `Loading`, `Loaded` and `Replaying` return `Bootstrapping`; `Withheld` and `Closed` permanently close admission and return `Closed`. Fills and builders admitted earlier keep their reservations or escrowed extents in every state.
//! - Every write of the word is one compare-and-swap from the value the writer read, made by the attached volume's owner turn or by [`Storage::withdraw`](super::Storage::withdraw); [`next`] decides each transition from a closed table with no default branch, so a writer that lost a race to `Withheld` changes nothing.
//! - A storage attaches once, so the word describes that one attach for the storage's life.

#[cfg(all(test, loom))]
use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(all(test, loom)))]
use std::sync::atomic::{AtomicU64, Ordering};

use super::reserve::ReserveError;

/// `State` is the recovery readiness of the attached volume, exported as `Readiness`; every state lies inside the storage's [`Phase::Live`](super::Phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Fills are allowed before a volume attaches. Attachment sets the authority field; fill reservations then fail with `Bootstrapping` while the state is `Detached`.
    Detached,
    /// The attach's bootstrap is running; new fills refuse.
    Loading,
    /// Both RESET roots persisted, or the warm bootstrap committed allocation readiness, and replay has not begun; new fills refuse until `Live`, which a matching `begin_replay` reaches over no restored binding and `complete_replay` reaches after one.
    Loaded,
    /// Replay began and the caller has not reported the tip; new fills refuse.
    Replaying,
    /// Replay's prerequisites hold; new fills proceed.
    Live,
    /// Fill admission withdrew for the rest of the attach; lookups and granted read rights keep working, except that a slot carrying the recovered-origin marker grants only while the word reads `Live`.
    Withheld,
    /// The attached volume closed; new fills refuse.
    Closed,
}

impl State {
    pub(crate) const ALL_STATES: [Self; 7] = [
        Self::Detached,
        Self::Loading,
        Self::Loaded,
        Self::Replaying,
        Self::Live,
        Self::Withheld,
        Self::Closed,
    ];

    /// `below_live` holds while the attached volume's load or replay is unfinished.
    pub(crate) fn below_live(self) -> bool {
        match self {
            Self::Loading | Self::Loaded | Self::Replaying => true,
            Self::Detached | Self::Live | Self::Withheld | Self::Closed => false,
        }
    }

    /// `initializing` holds from the attach until its load completes: `Detached` while the gate runs, then `Loading`.
    pub(crate) fn initializing(self) -> bool {
        match self {
            Self::Detached | Self::Loading => true,
            Self::Loaded | Self::Replaying | Self::Live | Self::Withheld | Self::Closed => false,
        }
    }

    pub(crate) fn fill_refusal(self) -> Option<ReserveError> {
        match self {
            Self::Detached | Self::Live => None,
            Self::Loading | Self::Loaded | Self::Replaying => Some(ReserveError::Bootstrapping),
            Self::Withheld | Self::Closed => Some(ReserveError::Closed),
        }
    }

    /// `stops_metadata` holds only for `Withheld`, the ended attempt that submits no further metadata command; a volume
    /// that [`Volume::close`](super::volume::Volume::close) closed ends metadata through its own closed flag.
    pub(crate) fn stops_metadata(self) -> bool {
        match self {
            Self::Withheld => true,
            Self::Detached
            | Self::Loading
            | Self::Loaded
            | Self::Replaying
            | Self::Live
            | Self::Closed => false,
        }
    }
}

// `Word` stores state discriminants, so `decode` and `ALL_STATES` must agree on all seven values, which the three bits `decode` masks hold.
const _: () = {
    let mut index = 0;
    while index < State::ALL_STATES.len() {
        let state = State::ALL_STATES[index];
        assert!(state as usize == index);
        assert!(decode(state as u64) as usize == index);
        index += 1;
    }
};

/// `Event` is one input the machine judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// The attached volume passed its gate and its bootstrap began.
    Attach,
    /// The load finished.
    LoadComplete,
    /// The caller began replay under a subscription; `matches` holds when its feed contract is the volume's and it starts at position zero, and `rows` counts admitted bindings.
    BeginReplay {
        matches: bool,
        rows: u64,
    },
    /// The caller reports replay reached the tip under the same subscription.
    CompleteReplay,
    /// The load or an image check withheld the attempt.
    Withhold,
    /// Health loss, authority withdrawal, or an attach gate refusal, which ends the attempt while the word reads `Detached`, where `Withhold` is an invariant error.
    Withdraw,
    Close,
}

/// Why an event changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessError {
    /// The event came too early: no volume passed its gate, the load is unfinished, or replay has not begun.
    NotReady,
    /// Replay already began or already reached Live.
    AlreadyLive,
    /// The attempt is withheld or closed and admits no replay.
    Ended(State),
    /// The event cannot happen in this state; the attempt's owner violated its sequence.
    Invariant,
}

/// `next` is the machine's closed table: the state `event` moves `state` to, or why it changes nothing.
///
/// # Errors
///
/// The [`ReadinessError`] the table names for the cell.
pub(crate) fn next(state: State, event: Event) -> Result<State, ReadinessError> {
    use Event::{Attach, BeginReplay, Close, CompleteReplay, LoadComplete, Withdraw, Withhold};
    use ReadinessError::{AlreadyLive, Ended, Invariant, NotReady};
    use State::{Closed, Detached, Live, Loaded, Loading, Replaying, Withheld};
    match (state, event) {
        (Detached, Attach) => Ok(Loading),
        (Detached, LoadComplete | BeginReplay { .. } | CompleteReplay) => Err(NotReady),
        (Detached, Withdraw) => Ok(Withheld),
        (Detached, Close) => Ok(Closed),
        (Detached, Withhold) => Err(Invariant),
        (Withheld, Attach) => Ok(Withheld),
        (Loading | Loaded | Replaying | Live | Closed, Attach) => Err(Invariant),
        (Loading, LoadComplete) => Ok(Loaded),
        (Loading, BeginReplay { .. } | CompleteReplay) => Err(NotReady),
        (Loading | Loaded | Replaying, Withhold | Withdraw) => Ok(Withheld),
        (Loading | Loaded | Replaying | Live | Withheld | Closed, Close) => Ok(Closed),
        (Loaded, LoadComplete) => Err(Invariant),
        (Loaded, BeginReplay { matches: false, .. }) => Ok(Withheld),
        (
            Loaded,
            BeginReplay {
                matches: true,
                rows: 0,
            },
        ) => Ok(Live),
        (Loaded, BeginReplay { matches: true, .. }) => Ok(Replaying),
        (Loaded, CompleteReplay) => Err(NotReady),
        (Replaying, LoadComplete) => Err(Invariant),
        (Replaying, BeginReplay { .. }) => Err(AlreadyLive),
        (Replaying, CompleteReplay) => Ok(Live),
        (Live, LoadComplete) => Err(Invariant),
        (Live, BeginReplay { .. } | CompleteReplay) => Err(AlreadyLive),
        (Live, Withhold | Withdraw) => Ok(Withheld),
        (Withheld, LoadComplete | Withhold | Withdraw) => Ok(Withheld),
        (Withheld, BeginReplay { .. } | CompleteReplay) => Err(Ended(Withheld)),
        (Closed, LoadComplete | Withhold | Withdraw) => Ok(Closed),
        (Closed, BeginReplay { .. } | CompleteReplay) => Err(Ended(Closed)),
    }
}

#[derive(Debug, Default)]
pub(crate) struct Word(AtomicU64);

impl Word {
    /// `state` reads the word. A reservation reads it under the pool gate, so the gate's release and acquire order it after any withdrawal that passed the gate first.
    pub(crate) fn state(&self) -> State {
        decode(self.0.load(Ordering::SeqCst))
    }

    #[inline]
    pub(crate) fn holds(&self, state: State) -> bool {
        self.0.load(Ordering::Relaxed) & 7 == state as u64
    }

    pub(crate) fn lineage(&self) -> u32 {
        (self.0.load(Ordering::Acquire) >> 32) as u32
    }

    /// Publishes `state`'s authority code and `lineage` by compare-and-swap, keeping the readiness field the word holds when the swap succeeds; a publication the word already holds writes nothing. The authority field reads 0 until the first publication.
    pub(crate) fn set_authority(&self, state: crate::failover::serving::State, lineage: u32) {
        use crate::failover::serving::State as S;
        let bits = (u64::from(lineage) << 32)
            | (match state {
                S::Withdrawn => WITHDRAWN,
                S::Serving => SERVING,
                S::Recovering => RECOVERING,
                S::PreBoundary | S::Closed => INACTIVE,
            } << 8);
        let mut current = self.0.load(Ordering::SeqCst);
        loop {
            let moved = (current & 7) | bits;
            if current == moved {
                return;
            }
            match self
                .0
                .compare_exchange(current, moved, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(seen) => current = seen,
            }
        }
    }

    pub(crate) fn authority_withdrawn(&self) -> bool {
        ((self.0.load(Ordering::Acquire) >> 8) & 15) == WITHDRAWN
    }

    /// The state and whether an attached volume's gate is running, from one load of the word. The gate counts as running while the word reads `Detached` after an attach set its authority field, a standby whose gate never starts included.
    pub(crate) fn state_and_attach_gate(&self) -> (State, bool) {
        let word = self.0.load(Ordering::SeqCst);
        (decode(word), awaiting_gate(word))
    }

    /// Whether, from one load of the word, an attached volume's gate runs or its load or replay is unfinished.
    pub(crate) fn attach_unfinished(&self) -> bool {
        let word = self.0.load(Ordering::SeqCst);
        decode(word).below_live() || awaiting_gate(word)
    }

    /// The refusal a new fill or builder takes, judged from one load of the word; `None` admits it. The first matching rule decides:
    ///
    /// 1. `None` at `Live` under `SERVING`.
    /// 2. `Closed` while readiness reads `Withheld` or `Closed`, under any authority.
    /// 3. `Withdrawn` under `WITHDRAWN`.
    /// 4. `Bootstrapping` under `RECOVERING`, or while an attached volume's gate runs.
    /// 5. Under `INACTIVE`, which `set_authority` writes for `PreBoundary` and `Closed`: `Bootstrapping` while the load or replay is unfinished, else `Closed`.
    /// 6. Under `UNPUBLISHED` or `SERVING`: `Bootstrapping` while the load or replay is unfinished, else `None`.
    pub(crate) fn fill_refusal(&self) -> Option<ReserveError> {
        let word = self.0.load(Ordering::Acquire);
        // This compare and the rules below both return `None` for `Live` under `Serving`.
        if word & FIELDS == (SERVING << 8) | State::Live as u64 {
            return None;
        }
        let authority = (word >> 8) & 15;
        if decode(word).fill_refusal() == Some(ReserveError::Closed) {
            return Some(ReserveError::Closed);
        }
        if authority == WITHDRAWN {
            return Some(ReserveError::Withdrawn);
        }
        if authority == RECOVERING || awaiting_gate(word) {
            return Some(ReserveError::Bootstrapping);
        }
        if authority != UNPUBLISHED && authority != SERVING {
            return Some(if decode(word).below_live() {
                ReserveError::Bootstrapping
            } else {
                ReserveError::Closed
            });
        }
        decode(word).fill_refusal()
    }

    /// Stores `state` as the whole word, bypassing the table and clearing every other field the word packs: a negative
    /// control's planted writer.
    #[cfg(all(test, loom))]
    pub(crate) fn force(&self, state: State) {
        self.0.store(state as u64, Ordering::SeqCst);
    }

    /// `apply` judges `event` against the word and writes the next state by one compare-and-swap, judging again when a concurrent writer moved the word first; a transition to the state the word already holds writes nothing.
    pub(crate) fn apply(&self, event: Event) -> Result<State, ReadinessError> {
        let mut current = self.0.load(Ordering::SeqCst);
        loop {
            let moved = next(decode(current), event)?;
            if moved as u64 == current & 7 {
                return Ok(moved);
            }
            match self.0.compare_exchange(
                current,
                (current & !7) | moved as u64,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(moved),
                Err(seen) => current = seen,
            }
        }
    }
}

/// The authority code before the attach's first `set_authority`. A `Live` word admits fills under this code or `SERVING`.
const UNPUBLISHED: u64 = 0;

/// The authority code `set_authority` writes for `PreBoundary` and `Closed`.
const INACTIVE: u64 = 1;

/// The authority code `set_authority` writes for `Withdrawn`.
const WITHDRAWN: u64 = 2;

/// The authority code `set_authority` writes for `Serving`.
const SERVING: u64 = 3;

/// The authority code `set_authority` writes for `Recovering`.
const RECOVERING: u64 = 4;

/// The mask of the readiness bits 0..3 and the authority bits 8..12.
const FIELDS: u64 = 0xF07;

/// Whether `word` reads `Detached` with a nonzero authority field, which only an attach sets.
const fn awaiting_gate(word: u64) -> bool {
    (word >> 8) & 15 != 0 && matches!(decode(word), State::Detached)
}

/// The state whose discriminant the word's low three bits hold; matching the masked discriminant lets the compiler evaluate state predicates directly from the word's bits. Every writer stores a discriminant, at most 6, so the field never holds 7; decoding 7 as `Closed` keeps the match total with no panic branch on the fill path, and that state refuses every fill.
const fn decode(word: u64) -> State {
    match word & 7 {
        0 => State::Detached,
        1 => State::Loading,
        2 => State::Loaded,
        3 => State::Replaying,
        4 => State::Live,
        5 => State::Withheld,
        6 | 7 => State::Closed,
        _ => panic!("`word & 7` is at most 7"),
    }
}

#[cfg(all(test, loom))]
mod authority_model {
    use super::*;
    use loom::{sync::Arc, thread};

    fn state_only_store() {
        loom::model(move || {
            let word = Arc::new(Word::default());
            word.apply(Event::Attach).unwrap();
            word.apply(Event::LoadComplete).unwrap();
            word.apply(Event::BeginReplay {
                matches: true,
                rows: 0,
            })
            .unwrap();
            let owner = Arc::clone(&word);
            let writer = thread::spawn(move || {
                owner.set_authority(crate::failover::serving::State::Serving, 1);
                owner.set_authority(crate::failover::serving::State::Withdrawn, 1);
                assert!(matches!(
                    owner.fill_refusal(),
                    Some(ReserveError::Withdrawn | ReserveError::Closed)
                ));
            });
            let reader = Arc::clone(&word);
            let read = thread::spawn(move || {
                if reader.state() == State::Withheld {
                    assert_eq!(reader.fill_refusal(), Some(ReserveError::Closed));
                }
            });
            word.0.store(State::Withheld as u64, Ordering::SeqCst);
            writer.join().unwrap();
            read.join().unwrap();
            assert_eq!(
                word.state(),
                State::Withheld,
                "readiness and authority fields remain intact"
            );
            assert_eq!(
                (word.lineage(), (word.0.load(Ordering::SeqCst) >> 8) & 15),
                (1, WITHDRAWN),
                "readiness and authority fields remain intact"
            );
            assert_eq!(word.fill_refusal(), Some(ReserveError::Closed));
        });
    }

    #[test]
    fn withdrawal_and_serving_publication_preserve_both_word_fields() {
        loom::model(move || {
            let word = Arc::new(Word::default());
            word.apply(Event::Attach).unwrap();
            word.apply(Event::LoadComplete).unwrap();
            word.apply(Event::BeginReplay {
                matches: true,
                rows: 0,
            })
            .unwrap();
            let owner = Arc::clone(&word);
            let writer = thread::spawn(move || {
                owner.set_authority(crate::failover::serving::State::Serving, 1);
                owner.set_authority(crate::failover::serving::State::Withdrawn, 1);
                assert!(matches!(
                    owner.fill_refusal(),
                    Some(ReserveError::Withdrawn | ReserveError::Closed)
                ));
            });
            let reader = Arc::clone(&word);
            let read = thread::spawn(move || {
                if reader.state() == State::Withheld {
                    assert_eq!(reader.fill_refusal(), Some(ReserveError::Closed));
                }
            });
            word.apply(Event::Withdraw).unwrap();
            writer.join().unwrap();
            read.join().unwrap();
            assert_eq!(
                word.state(),
                State::Withheld,
                "readiness and authority fields remain intact"
            );
            assert_eq!(
                (word.lineage(), (word.0.load(Ordering::SeqCst) >> 8) & 15),
                (1, WITHDRAWN),
                "readiness and authority fields remain intact"
            );
            assert_eq!(word.fill_refusal(), Some(ReserveError::Closed));
        });
    }

    #[test]
    #[should_panic(expected = "readiness and authority fields remain intact")]
    fn negative_control_a_state_only_store_loses_the_serving_lineage() {
        state_only_store();
    }
}
