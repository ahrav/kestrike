//! The extent allocator's placement, return and accounting decisions: which units a reservation keeps and which remainder it offers back, which run a return joins, which index key names a run, how many placeable units a free run holds, and whether a search's counted work fits its funded limit.
//!
//! The verifier checks these value-only decisions; the allocator applies them to its bitmap, summaries, index and ledger.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Bits of an index key below the length field.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const START_BITS: u32 = 40;
/// The length field of a run of at least this many units.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const SATURATED: u64 = 0xFF_FFFF;

/// A reservation of `n` units placed at the start of the free run `start..high` keeps `start..start + n` and leaves the remainder `start + n..high` free, returned as its start and length.
#[cfg_attr(verus_keep_ghost, verus_spec(rest =>
    requires start + n <= high,
    ensures rest.0 == start + n, rest.0 + rest.1 == high,
))]
#[inline(always)]
pub(super) fn remainder(start: u64, n: u64, high: u64) -> (u64, u64) {
    (start + n, high - start - n)
}

/// A return of `start..end` joins the `before` free units ending at `start` and the `after` free units starting at `end` into one run `low..high`.
#[cfg_attr(verus_keep_ghost, verus_spec(run =>
    requires before <= start, start < end, end + after <= u64::MAX,
    ensures run.0 == start - before, run.1 == end + after, run.0 <= start, end <= run.1,
))]
#[inline(always)]
pub(super) fn joined(start: u64, end: u64, before: u64, after: u64) -> (u64, u64) {
    (start - before, end + after)
}

/// The index key of the free run `start..start + len`: the start in the low [`START_BITS`] bits and the length, saturated at [`SATURATED`], above, so integer order is `(len.min(SATURATED), start)` order.
#[cfg_attr(verus_keep_ghost, verus_spec(key =>
    requires start < 0x100_0000_0000,
    ensures
        key as int == start as int + vstd::math::min(len as int, SATURATED as int) * 0x100_0000_0000,
))]
#[inline(always)]
pub(super) fn run_key(start: u64, len: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::key_packs(start, if len < SATURATED { len } else { SATURATED }); }
    start | len.min(SATURATED) << START_BITS
}

/// A key's start and its length field, the inverse of [`run_key`] for every key it builds.
#[cfg_attr(verus_keep_ghost, verus_spec(run =>
    ensures
        run.0 as int == key as int % 0x100_0000_0000,
        run.1 as int == key as int / 0x100_0000_0000,
))]
#[inline(always)]
pub(super) fn key_run(key: u64) -> (u64, u64) {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::key_unpacks(key); }
    (key & ((1 << START_BITS) - 1), key >> START_BITS)
}

/// The placeable units of a free run of `len` units under the positive full-extent charge `c`: the largest multiple of `c` at most `len`, so whole full extents fill it and fewer than `c` units stay over.
#[cfg_attr(verus_keep_ghost, verus_spec(placeable =>
    requires c > 0,
    ensures placeable <= len, len - placeable < c, placeable % c == 0,
))]
#[inline(always)]
pub(super) fn placeable(len: u64, c: u64) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(len as int, c as int);
        vstd::arithmetic::div_mod::lemma_mod_pos_bound(len as int, c as int);
        vstd::arithmetic::div_mod::lemma_div_pos_is_pos(len as int, c as int);
        vstd::arithmetic::mul::lemma_mul_nonnegative(c as int, len as int / c as int);
        vstd::arithmetic::mul::lemma_mul_is_commutative(c as int, len as int / c as int);
        vstd::arithmetic::div_mod::lemma_mod_multiples_basic(len as int / c as int, c as int);
    }
    len - len % c
}

/// Whether a search's counted visits fit its funded limit; the allocator takes a fit only when this holds.
#[cfg_attr(verus_keep_ghost, verus_spec(fits =>
    ensures fits == (work <= limit),
))]
#[inline(always)]
pub(super) fn within(work: usize, limit: usize) -> bool {
    work <= limit
}

/// A reservation debits its counted visits, capped at the limit its caller preflighted.
#[cfg_attr(verus_keep_ghost, verus_spec(debit =>
    ensures debit <= limit, debit <= work, debit == work || debit == limit,
))]
#[inline(always)]
pub(super) fn charged(work: usize, limit: usize) -> usize {
    work.min(limit)
}
