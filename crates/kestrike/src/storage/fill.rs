//! Safety invariant of the fill record word: a record is Free only after an
//! `Acquire` load, or a load followed by an `Acquire` fence, observed its
//! owner's `Release` departure, so every access the owner made before
//! departing, to the record's key and to the disposal of its extent, happens
//! before the observer's later accesses, the key's write for the next
//! occupant among them.
//!
//! A nonzero word carries the serial of the attempt occupying the record in
//! its upper bits and two flags in its lowest bits. `DEPARTED` is set once by
//! the attempt's unique owner as its last access. `REVOKED` is set once under
//! the shard gate, by an invalidation or by the publishing owner within its
//! own hold. The serial is issued under the gate from a per-shard counter
//! that starts at [`FIRST_SERIAL`] and only grows, so no two occupancies of
//! one record ever share a word, and a word whose serial was never issued is
//! malformed. The owner writes nothing after departing;
//! the departure compare-exchange checks the word still carries the owner's
//! serial, so a late owner can never mark a record its serial no longer
//! occupies. An owner that holds the shard gate and has revalidated its word
//! under that hold is the word's only possible writer until it releases the
//! gate, so it revokes and departs with plain stores instead. Revocation
//! clears the association only: the record stays occupied until its owner
//! departs and service releases it, so a same-key attempt begun after a
//! revocation takes another record and the old owner's cleanup reaches only
//! the old one.
//!
//! `depart`, `revoke`, `observe`, `load_run` and `release` are written over
//! an abstract word so the same code runs on the mapped state word and, under
//! `--cfg loom`, on a model atomic; `revoke_held` and `depart_held` take the
//! mapped word only.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const FREE: u64 = 0;

/// Serial zero is reserved for the Free word.
pub(crate) const FIRST_SERIAL: u64 = 1;

const DEPARTED: u64 = 1;
const REVOKED: u64 = 1 << 1;
const SERIAL_SHIFT: u32 = 2;

/// The largest serial a state word can carry; a shard whose next serial
/// would pass it issues no further attempt.
pub const SERIAL_MAX: u64 = u64::MAX >> SERIAL_SHIFT;

/// An attempt serial that fits above both flags in an occupied fill word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct FillSerial(NonZeroU64);

impl FillSerial {
    pub(crate) const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(serial) if value <= SERIAL_MAX => Some(Self(serial)),
            _ => None,
        }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}

pub(crate) trait FillWord {
    fn load(&self, order: Ordering) -> u64;
    fn store(&self, value: u64, order: Ordering);
    fn fetch_or(&self, value: u64, order: Ordering) -> u64;
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
    /// An `Acquire` fence of the word's atomic family, so a fence following
    /// a `Relaxed` load that read a `Release` store synchronizes with that
    /// store in the same model the word's own orderings are checked in.
    fn acquire_fence();
}

macro_rules! forward_fill_word {
    ($atomic:ty, $fence:path) => {
        impl FillWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u64 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn acquire_fence() {
                $fence(Ordering::Acquire);
            }

            #[inline(always)]
            fn store(&self, value: u64, order: Ordering) {
                Self::store(self, value, order)
            }

            #[inline(always)]
            fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_or(self, value, order)
            }

            #[inline(always)]
            fn compare_exchange(
                &self,
                current: u64,
                new: u64,
                success: Ordering,
                failure: Ordering,
            ) -> Result<u64, u64> {
                Self::compare_exchange(self, current, new, success, failure)
            }
        }
    };
}

forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);
#[cfg(all(test, loom))]
forward_fill_word!(loom::sync::atomic::AtomicU64, loom::sync::atomic::fence);

/// Whether `word`, the record an attempt of `serial` occupied, shows that
/// attempt's owner ended: it departed, or the record was freed or carries
/// another attempt's serial.
pub(crate) const fn ended(word: u64, serial: FillSerial) -> bool {
    word >> SERIAL_SHIFT != serial.get() || word & DEPARTED != 0
}

/// Whether `word` carries a revocation, set by an invalidation or by the
/// publishing owner's [`revoke_held`].
pub(crate) const fn revoked(word: u64) -> bool {
    word & REVOKED != 0
}

/// Whether `word` carries its owner's departure.
pub(crate) const fn departed(word: u64) -> bool {
    word & DEPARTED != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Record {
    Free,
    Occupied {
        serial: FillSerial,
        /// The owner made its last access.
        departed: bool,
        /// An invalidation, or the publishing owner within its own hold,
        /// cleared the record's association with the key.
        revoked: bool,
    },
}

impl Record {
    /// Whether the record is a key's current association: occupied and not
    /// revoked, whether or not its owner has departed.
    #[cfg(test)]
    pub(crate) fn is_associated(self) -> bool {
        matches!(self, Self::Occupied { revoked: false, .. })
    }

    pub(crate) fn is_departed(self) -> bool {
        matches!(self, Self::Occupied { departed: true, .. })
    }
}

/// A word no protocol step writes: flags without a serial, or a serial the
/// shard has not issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// The occupied words a shard has issued, as the span of their offsets from
/// the first occupied word, both flag bits included. The span saturates so a
/// counter past [`SERIAL_MAX`] holds every encodable serial and a counter at
/// [`FIRST_SERIAL`] holds none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Issued(u64);

impl Issued {
    /// The span covers words whose serials lie in
    /// `FIRST_SERIAL..next_serial.min(SERIAL_MAX + 1)`, where `next_serial`
    /// is the shard's next unissued serial.
    #[inline]
    pub(crate) fn before(next_serial: u64) -> Self {
        Self(next_serial.min(SERIAL_MAX + 1).saturating_sub(FIRST_SERIAL) << SERIAL_SHIFT)
    }

    /// Whether `word` is occupied and well formed: one subtraction and one
    /// comparison. The Free word and a word of flags alone lie below the
    /// first occupied word, so their offsets wrap past the span.
    #[inline]
    pub(crate) fn holds(self, word: u64) -> bool {
        word.wrapping_sub(FIRST_SERIAL << SERIAL_SHIFT) < self.0
    }
}

/// Decodes `word` against `next_serial`, the shard's next unissued serial.
///
/// An occupied word is valid when its serial lies in `FIRST_SERIAL..next_serial`,
/// which [`Issued`] checks.
///
/// # Errors
///
/// [`Malformed`] for a word outside the encoding.
#[inline]
pub(crate) fn decode(word: u64, next_serial: u64) -> Result<Record, Malformed> {
    if word == FREE {
        return Ok(Record::Free);
    }
    if !Issued::before(next_serial).holds(word) {
        return Err(Malformed);
    }
    let Some(serial) = NonZeroU64::new(serial(word)) else {
        return Err(Malformed);
    };
    Ok(Record::Occupied {
        // Removing the two flag bits bounds the serial by SERIAL_MAX.
        serial: FillSerial(serial),
        departed: word & DEPARTED != 0,
        revoked: word & REVOKED != 0,
    })
}

/// The serial an occupied word carries.
#[inline]
pub(crate) fn serial(word: u64) -> u64 {
    word >> SERIAL_SHIFT
}

/// The word of a record freshly occupied by `serial`.
#[inline]
pub(crate) fn occupied(serial: FillSerial) -> u64 {
    serial.get() << SERIAL_SHIFT
}

/// The owner's departure: sets `DEPARTED` with `Release` if the word still
/// carries `serial`, and reports whether it did. The first exchange expects
/// the word the grant wrote, so no load precedes it. A failure returns the
/// current word: one without `serial` or already departed ends the loop
/// unwritten, and a revoked one is retried and succeeds, since revocation
/// flips one bit once, so the loop runs at most twice.
#[inline]
pub(crate) fn depart<W: FillWord>(state: &W, serial: FillSerial) -> bool {
    let mut word = occupied(serial);
    loop {
        match state.compare_exchange(word, word | DEPARTED, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(current) => word = current,
        }
        if ended(word, serial) {
            return false;
        }
    }
}

/// Clears the record's association under the shard gate. The owner's
/// concurrent departure is a read-modify-write on the same word, so neither
/// flag is lost.
#[inline]
pub(crate) fn revoke<W: FillWord>(state: &W) {
    state.fetch_or(REVOKED, Ordering::Relaxed);
}

/// [`revoke`] by the record's own owner, as a `Relaxed` store of the whole
/// word. The caller must hold the shard gate and must have read the word,
/// under that hold, as `serial`'s, undeparted and unrevoked. Every other
/// writer of an occupied word holds the gate, and the owner's departure is
/// the only gate-free one, so no write lands between that read and this
/// store and the store loses no flag.
#[inline]
pub(crate) fn revoke_held(state: &AtomicU64, serial: FillSerial) {
    state.store(occupied(serial) | REVOKED, Ordering::Relaxed);
}

/// [`depart`] by the owner after [`revoke_held`] in the same gate hold: a
/// `Release` store of the revoked, departed word, sound for the reason
/// [`revoke_held`] is. The `Release` pairs with [`observe`]'s `Acquire` load
/// or [`load_run`]'s fence.
#[inline]
pub(crate) fn depart_held(state: &AtomicU64, serial: FillSerial) {
    state.store(occupied(serial) | REVOKED | DEPARTED, Ordering::Release);
}

/// An observation of one record: an `Acquire` load, so a departed word
/// carries the owner's release and every access the owner made happens
/// before the observer's later accesses, decoded against `next_serial`.
/// The service pass observes under the gate, and a follower observes its own
/// record without it.
///
/// # Errors
///
/// [`Malformed`] for a word outside the encoding.
#[inline]
pub(crate) fn observe<W: FillWord>(state: &W, next_serial: u64) -> Result<Record, Malformed> {
    decode(state.load(Ordering::Acquire), next_serial)
}

/// The service pass's observation of a run of `N` records under the gate:
/// `Relaxed` loads of every word, then one `Acquire` fence when any word
/// is occupied. A run of Free words has no departure to synchronize with;
/// otherwise the fence, sequenced after the load that read a departed word,
/// synchronizes with the owner's `Release` store of that word, so every
/// departed record in the run carries its owner's release as
/// [`observe`]'s load does. The words are returned undecoded so the caller
/// decides each record in order and stops at the first malformed one with
/// the records before it settled, as a run of single observations would.
#[inline]
pub(crate) fn load_run<W: FillWord, const N: usize>(states: &[W; N]) -> [u64; N] {
    let words = states.each_ref().map(|state| state.load(Ordering::Relaxed));
    if words.iter().fold(FREE, |any, word| any | word) != FREE {
        W::acquire_fence();
    }
    words
}

/// Returns a record [`observe`] found departed to Free, under the shard
/// gate. A plain store suffices: the departed owner writes nothing further,
/// a stale owner's exchange checks a serial the word no longer carries, and
/// every other write to an occupied word happens under the gate the caller
/// holds, so nothing can have changed the word since the observation.
#[inline]
pub(crate) fn release<W: FillWord>(state: &W) {
    state.store(FREE, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn fill_serial(value: u64) -> FillSerial {
        FillSerial::new(value).unwrap()
    }

    #[test]
    fn a_fill_serial_contains_only_values_that_fit_an_occupied_word() {
        for value in [0, SERIAL_MAX + 1, u64::MAX] {
            assert_eq!(FillSerial::new(value), None);
        }
        for value in [FIRST_SERIAL, SERIAL_MAX] {
            let serial = fill_serial(value);
            assert_eq!(serial.get(), value);
            assert_eq!(occupied(serial) >> SERIAL_SHIFT, value);
        }
    }

    /// The range comparison and the flag tests agree with the decoding on
    /// every boundary: the Free word, flags without a serial, the first and
    /// the last issued serial with each flag pair, the first unissued serial
    /// and the largest word, against counters at zero, at the first serial,
    /// in the middle, at the maximum and past it.
    #[test]
    fn the_issued_span_holds_exactly_the_occupied_words_decode_accepts() {
        for next in [0, FIRST_SERIAL, 2, 9, SERIAL_MAX, SERIAL_MAX + 1, u64::MAX] {
            let issued = Issued::before(next);
            let serials = [
                FIRST_SERIAL,
                2,
                8,
                9,
                next.wrapping_sub(1),
                next,
                SERIAL_MAX,
            ];
            let words = [FREE, DEPARTED, REVOKED, DEPARTED | REVOKED, u64::MAX]
                .into_iter()
                .chain(serials.into_iter().flat_map(|serial| {
                    [0, DEPARTED, REVOKED, DEPARTED | REVOKED]
                        .map(|flags| serial.wrapping_shl(SERIAL_SHIFT) | flags)
                }));
            for word in words {
                let in_range = (FIRST_SERIAL..next).contains(&serial(word));
                assert_eq!(
                    issued.holds(word),
                    in_range,
                    "word {word:#x} against {next}"
                );
                let decoded = decode(word, next);
                assert_eq!(
                    matches!(decoded, Ok(Record::Occupied { .. })),
                    in_range,
                    "word {word:#x} against {next}"
                );
                assert_eq!(
                    decoded.is_err(),
                    word != FREE && !in_range,
                    "word {word:#x} against {next}"
                );
                if let Ok(Record::Occupied {
                    departed: left,
                    revoked: ended,
                    ..
                }) = decoded
                {
                    assert_eq!((departed(word), revoked(word)), (left, ended));
                }
            }
        }
        // A counter at the first serial has issued nothing, and one past the
        // maximum has issued every encodable serial.
        assert!(!Issued::before(FIRST_SERIAL).holds(occupied(fill_serial(FIRST_SERIAL))));
        assert!(Issued::before(u64::MAX).holds(u64::MAX));
    }

    #[test]
    fn the_encoding_round_trips_and_rejects_unissued_serials() {
        assert_eq!(decode(FREE, FIRST_SERIAL), Ok(Record::Free));
        let word = occupied(fill_serial(7));
        assert_eq!(
            decode(word, 8),
            Ok(Record::Occupied {
                serial: fill_serial(7),
                departed: false,
                revoked: false,
            })
        );
        assert_eq!(decode(word, 7), Err(Malformed));
        assert_eq!(decode(DEPARTED, 8), Err(Malformed));
        assert_eq!(decode(REVOKED | DEPARTED, 8), Err(Malformed));
        assert_eq!(decode(REVOKED | DEPARTED, u64::MAX), Err(Malformed));
        assert_eq!(
            decode(occupied(fill_serial(1)), FIRST_SERIAL),
            Err(Malformed)
        );
        assert_eq!(decode(occupied(fill_serial(1)), 0), Err(Malformed));
        // The largest serial, with both flags, against a counter past the
        // maximum: the span saturates instead of wrapping.
        assert_eq!(
            decode(u64::MAX, SERIAL_MAX + 1),
            Ok(Record::Occupied {
                serial: fill_serial(SERIAL_MAX),
                departed: true,
                revoked: true,
            })
        );
        assert_eq!(decode(u64::MAX, u64::MAX).map(|_| ()), Ok(()));
        assert_eq!(
            decode(occupied(fill_serial(SERIAL_MAX)), SERIAL_MAX),
            Err(Malformed)
        );
        assert_eq!(
            occupied(fill_serial(SERIAL_MAX)) >> SERIAL_SHIFT,
            SERIAL_MAX
        );
        assert_eq!(SERIAL_MAX, (1 << 62) - 1);
    }

    #[test]
    fn departure_checks_the_serial_and_survives_a_concurrent_revocation() {
        let state = AtomicU64::new(occupied(fill_serial(3)));
        assert!(!depart(&state, fill_serial(4)));
        assert_eq!(state.load(Ordering::Relaxed), occupied(fill_serial(3)));
        revoke(&state);
        assert!(depart(&state, fill_serial(3)));
        assert_eq!(
            decode(state.load(Ordering::Relaxed), 4),
            Ok(Record::Occupied {
                serial: fill_serial(3),
                departed: true,
                revoked: true,
            })
        );
        assert!(!depart(&state, fill_serial(3)));
        assert!(observe(&state, 4).is_ok_and(Record::is_departed));
        release(&state);
        assert_eq!(state.load(Ordering::Relaxed), FREE);
        assert_eq!(observe(&state, 4), Ok(Record::Free));
    }

    /// The gate holder's revocation and departure store the words the
    /// read-modify-write forms would have produced, in that order, and the
    /// service release then frees the record exactly as after a gateless
    /// departure.
    #[test]
    fn a_held_revocation_and_departure_write_the_same_words_as_the_exchanges() {
        let held = AtomicU64::new(occupied(fill_serial(5)));
        let exchanged = AtomicU64::new(occupied(fill_serial(5)));
        revoke_held(&held, fill_serial(5));
        revoke(&exchanged);
        assert_eq!(
            held.load(Ordering::Relaxed),
            exchanged.load(Ordering::Relaxed)
        );
        assert_eq!(
            decode(held.load(Ordering::Relaxed), 6),
            Ok(Record::Occupied {
                serial: fill_serial(5),
                departed: false,
                revoked: true,
            })
        );
        depart_held(&held, fill_serial(5));
        assert!(depart(&exchanged, fill_serial(5)));
        assert_eq!(
            held.load(Ordering::Relaxed),
            exchanged.load(Ordering::Relaxed)
        );
        let record = observe(&held, 6).unwrap();
        assert!(record.is_departed() && !record.is_associated());
        release(&held);
        assert_eq!(held.load(Ordering::Relaxed), FREE);
    }

    /// A word whose first compare-exchange loses to a revocation landing in
    /// between: the departure retries once against the revoked word and
    /// succeeds, so both flags survive and exactly two exchanges ran.
    struct Racing {
        word: std::cell::Cell<u64>,
        exchanges: std::cell::Cell<usize>,
    }

    impl FillWord for Racing {
        fn load(&self, _: Ordering) -> u64 {
            self.word.get()
        }

        // A single-threaded double: nothing to order against.
        fn acquire_fence() {}

        fn store(&self, value: u64, _: Ordering) {
            self.word.set(value);
        }

        fn fetch_or(&self, value: u64, _: Ordering) -> u64 {
            let old = self.word.get();
            self.word.set(old | value);
            old
        }

        fn compare_exchange(
            &self,
            current: u64,
            new: u64,
            _: Ordering,
            _: Ordering,
        ) -> Result<u64, u64> {
            self.exchanges.set(self.exchanges.get() + 1);
            if self.exchanges.get() == 1 {
                self.word.set(current | REVOKED);
                return Err(self.word.get());
            }
            if self.word.get() != current {
                return Err(self.word.get());
            }
            self.word.set(new);
            Ok(current)
        }
    }

    #[test]
    fn a_departure_that_loses_to_a_revocation_retries_exactly_once() {
        let racing = Racing {
            word: std::cell::Cell::new(occupied(fill_serial(5))),
            exchanges: std::cell::Cell::new(0),
        };
        assert!(depart(&racing, fill_serial(5)));
        assert_eq!(racing.exchanges.get(), 2);
        assert_eq!(
            decode(racing.word.get(), 6),
            Ok(Record::Occupied {
                serial: fill_serial(5),
                departed: true,
                revoked: true,
            })
        );
        assert_eq!(observe(&racing, 6).map(Record::is_departed), Ok(true));
        assert_eq!(observe(&racing, 5), Err(Malformed));
    }

    #[test]
    fn association_ends_at_revocation_not_at_departure() {
        let live = decode(occupied(fill_serial(2)), 3).unwrap();
        assert!(live.is_associated() && !live.is_departed());
        let state = AtomicU64::new(occupied(fill_serial(2)));
        assert!(depart(&state, fill_serial(2)));
        let departed = decode(state.load(Ordering::Relaxed), 3).unwrap();
        assert!(departed.is_associated() && departed.is_departed());
        revoke(&state);
        let revoked = decode(state.load(Ordering::Relaxed), 3).unwrap();
        assert!(!revoked.is_associated() && revoked.is_departed());
        assert!(!Record::Free.is_associated() && !Record::Free.is_departed());
    }
}
