//! The per-shard sequence: one word that brackets every visible
//! bucket update so a reader can tell a coherent copy from a torn one.
//!
//! Stable values are even. A writer holding the shard gate moves the stable
//! `v` to the odd `v + 1`, issues a release fence, stores its fields and
//! links `Relaxed`, and commits the even `v + 2`; a reader loads a stable
//! even value, copies what it needs with `SeqCst` loads, and requires the
//! same value afterwards. The proof obligation: when both loads return the
//! even `v`, every copied field belongs to the state `v` committed. This
//! proves snapshot coherence; the grace protocol and the storage identity
//! carry the lifetime and aliasing arguments.
//!
//! The argument is the seqlock's, in happens-before. Suppose a reader's two
//! loads both return the even `v`. No field it copied came from a bracket
//! that began after `v`: such a writer's release fence is sequenced after
//! its odd store and before its field store, and the reader's `SeqCst` load
//! of that field is an acquire load that read the store, so the fence
//! synchronizes with the load and the odd store happens before the reader's
//! second sequence load, which then cannot read `v`. No field it copied
//! predates the bracket that committed `v`: that commit is a `SeqCst`, hence
//! release, store the reader's first load acquired, and every field store
//! of that bracket and of the brackets before it, ordered by the gate's
//! release/acquire handoff, happens before the reader's field loads, which
//! by coherence read those stores or later ones. The terminal store takes
//! the odd store's place for the bare stores that follow it: it is `SeqCst`
//! and followed by the same fence, and a later hold that mutates a terminal
//! shard issues the fence itself before its bare stores, since a fence
//! orders only the stores sequenced after it in its own thread; so a reader
//! that copied a bare store's value reads [`TERMINAL`] on its second load,
//! and the terminal value is never a value a reader started from. On x86
//! the fences compile to nothing and the `Relaxed` stores are plain stores.
//!
//! Two premises carry that argument and live outside this file. Every
//! sequence load, every commit and the terminal store are `SeqCst`, so the
//! sequence also sits in one total order with the admission cutoff and the
//! pin stores the storage layer's arguments place it against; a mapping's
//! removal enters that order through the commit that ends it, which every
//! copy of the removed identity whose second load accepted it precedes. The
//! odd store is `SeqCst` too, and its role is separate from the fence after
//! it. The fence carries the coherence argument above. The `SeqCst` store
//! places the odd value in the same total order, so a reader's `SeqCst`
//! load that returns the even `v` precedes the odd `v + 1` there: the
//! language-level fact the `publish` module's clock witness states, whose
//! hardware half lives with the platform clock. Every
//! bucket field load a copy is made of is `SeqCst`, an acquire load, and the
//! `Relaxed` loads outside the sequence check choose cache hints and nothing
//! a reader acts on; and every bucket field store is `Relaxed` and issued
//! behind the fence, between
//! [`Busy::begin`] and [`Busy::commit`], after [`terminate`], after the
//! fence a terminal shard's mutation issues, or after the fence a pending
//! pair's reservation or cancel issues outside a bracket. And the word's
//! modification order is strictly increasing: only the shard gate holder
//! writes it, the gate's release/acquire hands each holder the previous
//! commit, and the one
//! even value that can be stored twice, [`TERMINAL`], is rejected by
//! [`read_stable`] so no reader anchors on it.
//!
//! The word never wraps. [`TERMINAL`] is the last even value and is
//! reserved: a writer whose commit would land there stores it instead of
//! committing, and from then on the shard refuses publication and every
//! funded snapshot attempt on it is spent as contended. No reissue, reset or
//! rebuild exists.
//!
//! The protocol is written over an abstract word so the same code runs on
//! the mapped control word and, under `--cfg loom`, on a model atomic.

use std::sync::atomic::Ordering;

/// The reserved final even value.
pub(crate) const TERMINAL: u64 = u64::MAX - 1;

/// A 64-bit word read and written atomically, with the fence of its runtime.
pub(crate) trait SeqWord {
    /// An atomic load at `order`.
    fn load(&self, order: Ordering) -> u64;
    /// An atomic store at `order`.
    fn store(&self, value: u64, order: Ordering);
    /// A release fence: orders the sequence store before it ahead of the
    /// `Relaxed` field stores after it, for the reader's acquire loads.
    fn fence_release();
}

macro_rules! forward_seq_word {
    ($atomic:ty, $fence:path) => {
        impl SeqWord for $atomic {
            #[inline(always)]
            fn load(&self, order: Ordering) -> u64 {
                Self::load(self, order)
            }

            #[inline(always)]
            fn store(&self, value: u64, order: Ordering) {
                Self::store(self, value, order);
            }

            #[inline(always)]
            fn fence_release() {
                $fence(Ordering::Release);
            }
        }
    };
}

forward_seq_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);
#[cfg(all(test, loom))]
forward_seq_word!(loom::sync::atomic::AtomicU64, loom::sync::atomic::fence);

/// Why a reader or writer found no stable sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unstable {
    /// A writer is between its odd and even stores, or unwound between them.
    Busy,
    /// The shard is terminal.
    Terminal,
}

/// Loads the sequence and classifies it: `Ok(v)` for a stable even value.
#[inline(always)]
pub(crate) fn read_stable<W: SeqWord>(sequence: &W) -> Result<u64, Unstable> {
    let value = sequence.load(Ordering::SeqCst);
    if value == TERMINAL {
        Err(Unstable::Terminal)
    } else if value & 1 == 1 {
        Err(Unstable::Busy)
    } else {
        Ok(value)
    }
}

/// Whether the reader's second load still shows the value it started from.
#[inline(always)]
pub(crate) fn still<W: SeqWord>(sequence: &W, started: u64) -> bool {
    sequence.load(Ordering::SeqCst) == started
}

/// Whether a commit from stable `v` would land on [`TERMINAL`], so the
/// writer must transition the shard instead of committing.
#[inline(always)]
pub(crate) fn would_exhaust(stable: u64) -> bool {
    stable >= TERMINAL - 2
}

/// A writer's bracket around one commit: stores the odd value and issues the
/// release fence on creation, and stores the even value on
/// [`commit`](Self::commit). Nothing fallible may run between the two; the
/// caller has validated and prepaid everything before creating one. A
/// bracket dropped without a commit leaves the word odd for good: every
/// later reader reports the shard busy and every later writer treats the
/// odd value under an open gate as corruption.
#[must_use = "a dropped bracket leaves the shard sequence odd for good; call commit()"]
pub(crate) struct Busy<'w, W: SeqWord> {
    sequence: &'w W,
    stable: u64,
}

impl<'w, W: SeqWord> Busy<'w, W> {
    /// Moves `sequence` from stable `stable` to `stable + 1` with a `SeqCst`
    /// store, which places the odd value in the total order of the sequence
    /// loads, then fences so the `Relaxed` field stores that follow publish
    /// the odd value to any reader that acquires one of them (see the module
    /// documentation). The caller has checked [`would_exhaust`] is false.
    #[inline(always)]
    pub(crate) fn begin(sequence: &'w W, stable: u64) -> Self {
        debug_assert!(stable & 1 == 0 && !would_exhaust(stable));
        sequence.store(stable + 1, Ordering::SeqCst);
        W::fence_release();
        Self { sequence, stable }
    }

    /// Publishes the even value `stable + 2` and returns it.
    #[inline(always)]
    pub(crate) fn commit(self) -> u64 {
        let committed = self.stable + 2;
        self.sequence.store(committed, Ordering::SeqCst);
        committed
    }
}

/// Makes the shard terminal. The release fence after the `SeqCst` store
/// orders it before the unbracketed field stores a terminal shard's
/// mutations make.
#[inline(always)]
pub(crate) fn terminate<W: SeqWord>(sequence: &W) {
    sequence.store(TERMINAL, Ordering::SeqCst);
    W::fence_release();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    #[test]
    fn stable_busy_and_terminal_are_classified_and_the_bracket_advances_by_two() {
        let sequence = AtomicU64::new(0);
        assert_eq!(read_stable(&sequence), Ok(0));
        let busy = Busy::begin(&sequence, 0);
        assert_eq!(read_stable(&sequence), Err(Unstable::Busy));
        assert!(!still(&sequence, 0));
        busy.commit();
        assert_eq!(read_stable(&sequence), Ok(2));
        assert!(still(&sequence, 2));
        assert!(!still(&sequence, 0));
        assert!(!would_exhaust(TERMINAL - 4));
        assert!(would_exhaust(TERMINAL - 2));
        assert!(would_exhaust(TERMINAL));
        terminate(&sequence);
        assert_eq!(read_stable(&sequence), Err(Unstable::Terminal));
        assert_eq!(TERMINAL & 1, 0);
    }
}
