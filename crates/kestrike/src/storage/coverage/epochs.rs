//! The retirement-epoch word's atomic operations: one compare-and-swap over the whole word registers a retirement under the current epoch, and one `fetch_sub` ends a registration in the pool-gate hold that retires its slot or, for a parked retirement service leaves unretired, in the gate hold whose `end_parked` converts the park; a park whose retirement loses the capture mutex keeps its registration until a later pass retires it.
//!
//! Every access to the word is `SeqCst`, and a registrant's CAS retries on the word it failed against.

use std::sync::atomic::Ordering::SeqCst;

use super::step::{CLOSED, count, registered, unit};

/// A word the operations below run on.
pub(crate) trait EpochWord {
    fn load(&self) -> u64;
    fn compare_exchange(&self, current: u64, next: u64) -> Result<u64, u64>;
    fn fetch_or(&self, bits: u64) -> u64;
    fn fetch_sub(&self, amount: u64) -> u64;
}

macro_rules! epoch_word {
    ($word:ty) => {
        impl EpochWord for $word {
            fn load(&self) -> u64 {
                <$word>::load(self, SeqCst)
            }
            fn compare_exchange(&self, current: u64, next: u64) -> Result<u64, u64> {
                <$word>::compare_exchange(self, current, next, SeqCst, SeqCst)
            }
            fn fetch_or(&self, bits: u64) -> u64 {
                <$word>::fetch_or(self, bits, SeqCst)
            }
            fn fetch_sub(&self, amount: u64) -> u64 {
                <$word>::fetch_sub(self, amount, SeqCst)
            }
        }
    };
}

epoch_word!(std::sync::atomic::AtomicU64);

/// Registers one retirement under the current epoch and returns that epoch, or `None` once admission is closed; a count at its limit sets the latch, which closes coverage admission, and the retirement proceeds uncounted.
pub(crate) fn register(word: &impl EpochWord) -> Option<u64> {
    let mut current = word.load();
    loop {
        let Some((next, epoch)) = registered(current) else {
            if current & CLOSED == 0 {
                word.fetch_or(CLOSED);
            }
            return None;
        };
        match word.compare_exchange(current, next) {
            Ok(_) => return Some(epoch),
            Err(seen) => current = seen,
        }
    }
}

/// Ends one registration under `epoch`.
///
/// # Panics
///
/// When the epoch counts no registration: every decrement follows its own registration.
pub(crate) fn release(word: &impl EpochWord, epoch: u64) {
    let previous = word.fetch_sub(unit(epoch));
    assert!(
        count(previous, epoch) > 0,
        "a decrement without its registration"
    );
}

/// Whether coverage admission is closed by an exhausted count.
pub(crate) fn exhausted(word: &impl EpochWord) -> bool {
    word.load() & CLOSED != 0
}
