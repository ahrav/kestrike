//! The word-level steps of lease-credit accounting, shared by the `lease`
//! module in production and by the `credit_model` loom kernel: each step is
//! generic over the atomic words it moves and over the [`Strength`] of its
//! orderings, so the model runs the same code on loom atomics.
//!
//! A record holds credits in words read as signed counts: a take subtracts
//! before it knows whether a credit was there and gives the credit back when
//! none was, so a word is below zero between those two steps and holds
//! nothing then. One bit per record in a map word says the record may hold
//! credits in some word. The invariant the steps keep: a record with credits
//! in any word has its bit set, or a scan is between its clear of the bit
//! and the reload that sets it back.
//!
//! The store-then-load pair that keeps the invariant is [`park`]'s add
//! followed by its load of the bit, against [`clear`]'s clear followed by
//! the scan's reload of the words. In production both pairs are `SeqCst`
//! accesses, so the four sit in one total order: whichever of the add and
//! the clear comes first, either the park's load sees the bit clear and
//! sets it, or the scan's reload sees the credit. The model encodes the same
//! constraint as `Release`/`Acquire` accesses with a `SeqCst` fence between
//! the two accesses of each pair, since loom 0.7.2 does not model the
//! cross-location total order of `SeqCst` accesses; dropping either fence,
//! or both, is one of the model's negative controls.

use std::sync::atomic::Ordering;

/// A word holding one record's credits.
pub(crate) trait CreditWord {
    fn load(&self, order: Ordering) -> usize;
    fn fetch_add(&self, value: usize, order: Ordering) -> usize;
    fn fetch_sub(&self, value: usize, order: Ordering) -> usize;
}

/// A 64-bit word whose bits each writer sets, clears or flips with one
/// read-modify-write: a parked-credit map word, a parked-set word, or a
/// slot's lifetime word under the policy's bit writes.
pub(crate) trait BitWord {
    fn load(&self, order: Ordering) -> u64;
    fn fetch_or(&self, value: u64, order: Ordering) -> u64;
    fn fetch_and(&self, value: u64, order: Ordering) -> u64;
    fn fetch_xor(&self, value: u64, order: Ordering) -> u64;
}

macro_rules! forward_credit_word {
    ($atomic:ty) => {
        impl CreditWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> usize {
                Self::load(self, order)
            }

            #[inline(always)]
            fn fetch_add(&self, value: usize, order: Ordering) -> usize {
                Self::fetch_add(self, value, order)
            }

            #[inline(always)]
            fn fetch_sub(&self, value: usize, order: Ordering) -> usize {
                Self::fetch_sub(self, value, order)
            }
        }
    };
}

macro_rules! forward_bit_word {
    ($atomic:ty) => {
        impl BitWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u64 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn fetch_or(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_or(self, value, order)
            }

            #[inline(always)]
            fn fetch_and(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_and(self, value, order)
            }

            #[inline(always)]
            fn fetch_xor(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_xor(self, value, order)
            }
        }
    };
}

/// A parked-map word's sweep counts: sweeps in progress in the low 32 bits,
/// sweeps started in the high 32.
pub(crate) trait SweepWord {
    fn load(&self, order: Ordering) -> u64;
    fn fetch_add(&self, value: u64, order: Ordering) -> u64;
    fn fetch_sub(&self, value: u64, order: Ordering) -> u64;
}

macro_rules! forward_sweep_word {
    ($atomic:ty) => {
        impl SweepWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u64 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_add(self, value, order)
            }

            #[inline(always)]
            fn fetch_sub(&self, value: u64, order: Ordering) -> u64 {
                Self::fetch_sub(self, value, order)
            }
        }
    };
}

forward_credit_word!(std::sync::atomic::AtomicUsize);
forward_bit_word!(std::sync::atomic::AtomicU64);
forward_sweep_word!(std::sync::atomic::AtomicU64);
#[cfg(all(test, loom))]
forward_credit_word!(loom::sync::atomic::AtomicUsize);
#[cfg(all(test, loom))]
forward_bit_word!(loom::sync::atomic::AtomicU64);
#[cfg(all(test, loom))]
forward_sweep_word!(loom::sync::atomic::AtomicU64);

/// A loom word whose read-modify-writes are a load and a plain store, both
/// `Relaxed` whatever order the caller asks for, so a write landing between
/// the two is overwritten: the models' negative control for each body that
/// relies on one read-modify-write.
#[cfg(all(test, loom))]
pub(crate) struct PlainBits<'a>(pub(crate) &'a loom::sync::atomic::AtomicU64);

#[cfg(all(test, loom))]
impl PlainBits<'_> {
    fn replace(&self, next: impl Fn(u64) -> u64) -> u64 {
        let current = self.0.load(Ordering::Relaxed);
        self.0.store(next(current), Ordering::Relaxed);
        current
    }
}

#[cfg(all(test, loom))]
impl BitWord for PlainBits<'_> {
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    fn fetch_or(&self, value: u64, _: Ordering) -> u64 {
        self.replace(|current| current | value)
    }

    fn fetch_and(&self, value: u64, _: Ordering) -> u64 {
        self.replace(|current| current & value)
    }

    fn fetch_xor(&self, value: u64, _: Ordering) -> u64 {
        self.replace(|current| current ^ value)
    }
}

/// Memory orderings of the two store-then-load pairs. [`Sequential`] is
/// production.
pub(crate) trait Strength {
    /// A park's add to a credit word.
    const ADD: Ordering;
    /// A park's load of the map word after its add.
    const BIT_LOAD: Ordering;
    /// A scan's clear of the bits of the records it found empty.
    const CLEAR: Ordering;
    /// A scan's reload of a cleared record's words.
    const RELOAD: Ordering;

    /// Fence after a park's add, before its load of the bit. Empty when the
    /// accesses themselves are `SeqCst`.
    #[inline(always)]
    fn fence_park() {}

    /// Fence after a scan's clear, before its reloads.
    #[inline(always)]
    fn fence_clear() {}
}

/// Production strength: `SeqCst` at both pairs.
pub(crate) struct Sequential;

impl Strength for Sequential {
    const ADD: Ordering = Ordering::SeqCst;
    const BIT_LOAD: Ordering = Ordering::SeqCst;
    const CLEAR: Ordering = Ordering::SeqCst;
    const RELOAD: Ordering = Ordering::SeqCst;
}

/// The credits `word` holds: its count read as signed, floored at zero.
#[inline(always)]
pub(crate) fn credits<W: CreditWord>(word: &W, order: Ordering) -> usize {
    (word.load(order) as isize).max(0) as usize
}

/// Adds `count` credits to `word`; when the add takes the word from holding
/// none to holding some, makes sure `bit` is set in `map`. A word that
/// already held credits has the record's bit set, or a scan is between its
/// clear and its reload, so such an add needs no load.
#[inline(always)]
pub(crate) fn park<S: Strength, W: CreditWord, M: BitWord>(
    word: &W,
    map: &M,
    bit: u64,
    count: usize,
) {
    let previous = word.fetch_add(count, S::ADD) as isize;
    if previous <= 0 && previous + count as isize > 0 {
        S::fence_park();
        if map.load(S::BIT_LOAD) & bit == 0 {
            map.fetch_or(bit, Ordering::SeqCst);
        }
    }
}

/// Takes up to `share` credits from `word` with one unconditional subtract,
/// at least one: what the word held, when fewer, with the excess given back
/// through [`park`] in the same step. Returns how many were taken; zero
/// when the word held none.
#[inline(always)]
pub(crate) fn take<S: Strength, W: CreditWord, M: BitWord>(
    word: &W,
    map: &M,
    bit: u64,
    share: usize,
) -> usize {
    let previous = word.fetch_sub(share, Ordering::Relaxed) as isize;
    if previous >= share as isize {
        return share;
    }
    let taken = previous.max(0) as usize;
    park::<S, W, M>(word, map, bit, share - taken);
    taken
}

/// Drains through [`take`], so a give-back owed to a word below zero lands
/// as a repayment and never as a credit another take could take. Credits
/// that land after the load stay in the word.
#[inline(always)]
pub(crate) fn drain<S: Strength, W: CreditWord, M: BitWord>(word: &W, map: &M, bit: u64) -> usize {
    match credits(word, Ordering::Relaxed) {
        0 => 0,
        seen => take::<S, W, M>(word, map, bit, seen),
    }
}

/// Clears `bits` in `map`, the records a scan found empty, ahead of the
/// scan's reload of each of them.
#[inline(always)]
pub(crate) fn clear<S: Strength, M: BitWord>(map: &M, bits: u64) {
    map.fetch_and(!bits, S::CLEAR);
    S::fence_clear();
}

/// Sets `bits` back in `map`: the records a scan's reload found holding
/// credits after its clear.
#[inline(always)]
pub(crate) fn reset<M: BitWord>(map: &M, bits: u64) {
    map.fetch_or(bits, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::{CreditWord, Sequential, drain, park, take};

    const BIT: u64 = 1;

    /// A credit word that runs `between` on the inner atomic right after the
    /// first access made through it, so a test places another reader's
    /// steps between two steps of the code under test.
    type Between<'a> = Box<dyn FnOnce(&AtomicUsize) + 'a>;

    struct Interleaved<'a> {
        word: AtomicUsize,
        between: Cell<Option<Between<'a>>>,
    }

    impl<'a> Interleaved<'a> {
        fn new(value: isize, between: impl FnOnce(&AtomicUsize) + 'a) -> Self {
            Self {
                word: AtomicUsize::new(value as usize),
                between: Cell::new(Some(Box::new(between))),
            }
        }

        fn after<T>(&self, value: T) -> T {
            if let Some(between) = self.between.take() {
                between(&self.word);
            }
            value
        }
    }

    impl CreditWord for Interleaved<'_> {
        fn load(&self, order: Ordering) -> usize {
            self.after(self.word.load(order))
        }

        fn fetch_add(&self, value: usize, order: Ordering) -> usize {
            self.after(self.word.fetch_add(value, order))
        }

        fn fetch_sub(&self, value: usize, order: Ordering) -> usize {
            self.after(self.word.fetch_sub(value, order))
        }
    }

    /// A word at -1 holds no credit: one reader took the last credit and a
    /// second reader's subtract found none and owes its give-back. A drain
    /// racing that give-back and a third reader's take moves out nothing,
    /// the third reader takes nothing, and the word ends at zero once the
    /// give-back lands.
    #[test]
    fn a_drain_racing_a_give_back_and_a_take_creates_no_credit() {
        let map = AtomicU64::new(BIT);
        let third = Cell::new(0);
        let word = Interleaved::new(-1, |inner| {
            park::<Sequential, _, _>(inner, &map, BIT, 1);
            third.set(take::<Sequential, _, _>(inner, &map, BIT, 1));
        });
        let drained = drain::<Sequential, _, _>(&word, &map, BIT);
        assert_eq!(
            drained + third.get(),
            0,
            "credits out of a word that held none"
        );
        assert_eq!(
            word.word.load(Ordering::Relaxed) as isize,
            0,
            "debt left behind"
        );
    }
}
