use vstd::prelude::*;

use crate::model::{head, joins, longest, splits, tail};

verus! {

pub(crate) open spec fn free_on(b: spec_fn(int) -> bool, lo: int, hi: int) -> bool {
    forall|u: int| lo <= u < hi ==> #[trigger] b(u)
}

pub(crate) open spec fn taken_on(b: spec_fn(int) -> bool, lo: int, hi: int) -> bool {
    forall|u: int| lo <= u < hi ==> !#[trigger] b(u)
}

pub(crate) open spec fn agree_on(b: spec_fn(int) -> bool, c: spec_fn(int) -> bool, lo: int, hi: int) -> bool {
    forall|u: int| lo <= u < hi ==> #[trigger] b(u) == c(u)
}

pub(crate) proof fn bounds(b: spec_fn(int) -> bool, lo: int, hi: int)
    ensures
        0 <= head(b, lo, hi),
        0 <= tail(b, lo, hi),
        tail(b, lo, hi) <= longest(b, lo, hi),
        lo <= hi ==> head(b, lo, hi) <= hi - lo,
        lo <= hi ==> tail(b, lo, hi) <= hi - lo,
        lo <= hi ==> longest(b, lo, hi) <= hi - lo,
    decreases hi - lo,
{
    if lo < hi {
        bounds(b, lo + 1, hi);
        bounds(b, lo, hi - 1);
    }
}

pub(crate) proof fn full(b: spec_fn(int) -> bool, lo: int, hi: int)
    requires
        lo <= hi,
    ensures
        head(b, lo, hi) == hi - lo <==> free_on(b, lo, hi),
        tail(b, lo, hi) == hi - lo <==> free_on(b, lo, hi),
        free_on(b, lo, hi) ==> longest(b, lo, hi) == hi - lo,
    decreases hi - lo,
{
    if lo < hi {
        full(b, lo + 1, hi);
        full(b, lo, hi - 1);
        if b(lo) && free_on(b, lo + 1, hi) {
            assert forall|u: int| lo <= u < hi implies #[trigger] b(u) by {}
        }
        if b(hi - 1) && free_on(b, lo, hi - 1) {
            assert forall|u: int| lo <= u < hi implies #[trigger] b(u) by {}
        }
        if free_on(b, lo, hi) {
            assert forall|u: int| lo + 1 <= u < hi implies #[trigger] b(u) by {}
            assert forall|u: int| lo <= u < hi - 1 implies #[trigger] b(u) by {}
        }
    }
}

pub(crate) proof fn same(b: spec_fn(int) -> bool, c: spec_fn(int) -> bool, lo: int, hi: int)
    requires
        agree_on(b, c, lo, hi),
    ensures
        head(b, lo, hi) == head(c, lo, hi),
        tail(b, lo, hi) == tail(c, lo, hi),
        longest(b, lo, hi) == longest(c, lo, hi),
    decreases hi - lo,
{
    if lo < hi {
        assert forall|u: int| lo + 1 <= u < hi implies #[trigger] b(u) == c(u) by {}
        assert forall|u: int| lo <= u < hi - 1 implies #[trigger] b(u) == c(u) by {}
        same(b, c, lo + 1, hi);
        same(b, c, lo, hi - 1);
    }
}

pub(crate) proof fn head_concat(b: spec_fn(int) -> bool, lo: int, mid: int, hi: int)
    requires
        lo <= mid <= hi,
    ensures
        head(b, lo, hi) == if head(b, lo, mid) == mid - lo {
            mid - lo + head(b, mid, hi)
        } else {
            head(b, lo, mid)
        },
    decreases mid - lo,
{
    if lo < mid {
        head_concat(b, lo + 1, mid, hi);
    }
}

pub(crate) proof fn tail_concat(b: spec_fn(int) -> bool, lo: int, mid: int, hi: int)
    requires
        lo <= mid <= hi,
    ensures
        tail(b, lo, hi) == if tail(b, mid, hi) == hi - mid {
            hi - mid + tail(b, lo, mid)
        } else {
            tail(b, mid, hi)
        },
    decreases hi - mid,
{
    if mid < hi {
        tail_concat(b, lo, mid, hi - 1);
    }
}

pub(crate) proof fn longest_concat(b: spec_fn(int) -> bool, lo: int, mid: int, hi: int)
    requires
        lo <= mid <= hi,
    ensures
        longest(b, lo, hi) == vstd::math::max(
            vstd::math::max(longest(b, lo, mid), longest(b, mid, hi)),
            tail(b, lo, mid) + head(b, mid, hi),
        ),
    decreases hi - mid,
{
    bounds(b, lo, mid);
    if mid < hi {
        longest_concat(b, lo, mid, hi - 1);
        tail_concat(b, lo, mid, hi);
        head_concat(b, mid, hi - 1, hi);
        full(b, mid, hi - 1);
        assert(head(b, hi, hi) == 0);
    }
}

pub(crate) open spec fn join_facts(
    was: spec_fn(int) -> bool,
    now: spec_fn(int) -> bool,
    low: int,
    high: int,
    n0: int,
    n1: int,
) -> bool {
    &&& head(now, n0, n1) == if low <= n0 { vstd::math::min(high, n1) - n0 } else { head(was, n0, n1) }
    &&& tail(now, n0, n1) == if high >= n1 { n1 - vstd::math::max(low, n0) } else { tail(was, n0, n1) }
    &&& longest(now, n0, n1) == vstd::math::max(
        longest(was, n0, n1),
        vstd::math::min(high, n1) - vstd::math::max(low, n0),
    )
}

proof fn joined_one(
    was: spec_fn(int) -> bool,
    now: spec_fn(int) -> bool,
    low: int,
    high: int,
    n0: int,
    n1: int,
)
    requires
        0 <= n0 < n1,
        low < n1,
        n0 < high,
        joins(was, now, low, high),
    ensures
        join_facts(was, now, low, high, n0, n1),
{
    let l = vstd::math::max(low, n0);
    let h = vstd::math::min(high, n1);
    assert forall|u: int| l <= u < h implies #[trigger] now(u) by {}
    assert forall|u: int| n0 <= u < l implies #[trigger] was(u) == now(u) by {}
    assert forall|u: int| h <= u < n1 implies #[trigger] was(u) == now(u) by {}
    full(now, l, h);
    same(was, now, n0, l);
    same(was, now, h, n1);
    three_parts(was, n0, l, h, n1);
    three_parts(now, n0, l, h, n1);
}

pub(crate) proof fn joined_runs(low: int, high: int, n0: int, n1: int)
    requires
        0 <= n0 < n1,
        low < n1,
        n0 < high,
    ensures
        forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
            #[trigger] joins(was, now, low, high) ==> join_facts(was, now, low, high, n0, n1),
{
    assert forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
        #[trigger] joins(was, now, low, high) implies join_facts(was, now, low, high, n0, n1) by {
        joined_one(was, now, low, high, n0, n1);
    }
}

pub(crate) proof fn none(b: spec_fn(int) -> bool, lo: int, hi: int)
    requires
        lo <= hi,
        taken_on(b, lo, hi),
    ensures
        head(b, lo, hi) == 0,
        tail(b, lo, hi) == 0,
        longest(b, lo, hi) == 0,
    decreases hi - lo,
{
    if lo < hi {
        assert forall|u: int| lo <= u < hi - 1 implies !#[trigger] b(u) by {}
        none(b, lo, hi - 1);
    }
}

pub(crate) open spec fn split_facts(
    was: spec_fn(int) -> bool,
    now: spec_fn(int) -> bool,
    low: int,
    start: int,
    end: int,
    high: int,
    n0: int,
    n1: int,
) -> bool {
    let part = vstd::math::min(high, n1) - vstd::math::max(low, n0);
    &&& head(now, n0, n1) == if low <= n0 {
        vstd::math::max(start - n0, 0)
    } else {
        head(was, n0, n1)
    }
    &&& tail(now, n0, n1) == if high >= n1 {
        vstd::math::max(n1 - end, 0)
    } else {
        tail(was, n0, n1)
    }
    &&& part <= longest(was, n0, n1)
    &&& part < longest(was, n0, n1) ==> longest(now, n0, n1) == longest(was, n0, n1)
    &&& low <= n0 && n1 <= high ==> longest(now, n0, n1) == vstd::math::max(
        head(now, n0, n1),
        tail(now, n0, n1),
    )
}

proof fn split_one(
    was: spec_fn(int) -> bool,
    now: spec_fn(int) -> bool,
    low: int,
    start: int,
    end: int,
    high: int,
    n0: int,
    n1: int,
)
    requires
        0 <= n0 < n1,
        start < n1,
        n0 < end,
        splits(was, now, low, start, end, high),
    ensures
        split_facts(was, now, low, start, end, high, n0, n1),
{
    let l = vstd::math::max(low, n0);
    let h = vstd::math::min(high, n1);
    let s = vstd::math::max(start, n0);
    let e = vstd::math::min(end, n1);
    assert forall|u: int| l <= u < h implies #[trigger] was(u) by {}
    assert forall|u: int| l <= u < s implies #[trigger] now(u) by {}
    assert forall|u: int| e <= u < h implies #[trigger] now(u) by {}
    assert forall|u: int| s <= u < e implies !#[trigger] now(u) by {}
    assert forall|u: int| n0 <= u < n1 && #[trigger] now(u) implies was(u) by {}
    assert forall|u: int| n0 <= u < l implies #[trigger] was(u) == now(u) by {}
    assert forall|u: int| h <= u < n1 implies #[trigger] was(u) == now(u) by {}
    full(was, l, h);
    full(now, l, s);
    full(now, e, h);
    none(now, s, e);
    same(was, now, n0, l);
    same(was, now, h, n1);
    three_parts(was, n0, l, h, n1);
    three_parts(now, n0, l, h, n1);
    head_concat(now, n0, s, n1);
    tail_concat(now, n0, e, n1);
    longest_concat(now, n0, s, n1);
    longest_concat(now, s, e, n1);
}

/// The start, end and longest runs of `n0..n1` in terms of its three parts `n0..l`, `l..h` and `h..n1`, with each part's bounds.
proof fn three_parts(b: spec_fn(int) -> bool, n0: int, l: int, h: int, n1: int)
    requires
        n0 <= l <= h <= n1,
    ensures
        head(b, n0, n1) == if head(b, n0, l) == l - n0 {
            l - n0 + head(b, l, n1)
        } else {
            head(b, n0, l)
        },
        head(b, l, n1) == if head(b, l, h) == h - l {
            h - l + head(b, h, n1)
        } else {
            head(b, l, h)
        },
        tail(b, n0, n1) == if tail(b, h, n1) == n1 - h {
            n1 - h + tail(b, n0, h)
        } else {
            tail(b, h, n1)
        },
        tail(b, n0, h) == if tail(b, l, h) == h - l {
            h - l + tail(b, n0, l)
        } else {
            tail(b, l, h)
        },
        longest(b, n0, n1) == vstd::math::max(
            vstd::math::max(longest(b, n0, l), longest(b, l, n1)),
            tail(b, n0, l) + head(b, l, n1),
        ),
        longest(b, l, n1) == vstd::math::max(
            vstd::math::max(longest(b, l, h), longest(b, h, n1)),
            tail(b, l, h) + head(b, h, n1),
        ),
        0 <= head(b, n0, l) <= l - n0,
        0 <= tail(b, n0, l) <= longest(b, n0, l) <= l - n0,
        0 <= head(b, h, n1) <= n1 - h,
        0 <= tail(b, h, n1) <= longest(b, h, n1) <= n1 - h,
        0 <= head(b, l, h) <= h - l,
        0 <= tail(b, l, h) <= longest(b, l, h) <= h - l,
        head(b, n0, l) == l - n0 <==> tail(b, n0, l) == l - n0,
        head(b, h, n1) == n1 - h <==> tail(b, h, n1) == n1 - h,
        head(b, n1, n1) == 0,
        tail(b, n0, n0) == 0,
{
    head_concat(b, n0, l, n1);
    head_concat(b, l, h, n1);
    tail_concat(b, n0, h, n1);
    tail_concat(b, n0, l, h);
    longest_concat(b, n0, l, n1);
    longest_concat(b, l, h, n1);
    bounds(b, n0, l);
    bounds(b, h, n1);
    bounds(b, l, h);
    full(b, n0, l);
    full(b, h, n1);
}

pub(crate) proof fn split_runs(low: int, start: int, end: int, high: int, n0: int, n1: int)
    requires
        0 <= n0 < n1,
        start < n1,
        n0 < end,
    ensures
        forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
            #[trigger] splits(was, now, low, start, end, high)
                ==> split_facts(was, now, low, start, end, high, n0, n1),
{
    assert forall|was: spec_fn(int) -> bool, now: spec_fn(int) -> bool|
        #[trigger] splits(was, now, low, start, end, high)
            implies split_facts(was, now, low, start, end, high, n0, n1) by {
        split_one(was, now, low, start, end, high, n0, n1);
    }
}

/// Concrete bitmaps satisfy the join and split relations, so a contract that assumes one constrains real runs.
pub(crate) proof fn witnesses() {
    let was: spec_fn(int) -> bool = |u: int| u == 1;
    let now: spec_fn(int) -> bool = |u: int| 1 <= u < 4;
    let after: spec_fn(int) -> bool = |u: int| u == 1 || u == 3;
    assert(joins(was, now, 1, 4));
    assert(splits(now, after, 1, 2, 3, 4));
}

pub(crate) proof fn shift_is_division(token: u64)
    ensures
        token >> 16u32 == token / 0x10000,
{
    assert(token >> 16u32 == token / 0x10000) by (bit_vector);
}

pub(crate) proof fn next_generation(token: u64)
    requires
        (token as int) / 0x10000 < 0xFFFF_FFFF_FFFF,
    ensures
        1u64 << 16u32 == 0x10000,
        token as int + 0x10000 <= u64::MAX,
        (token as int + 0x10000) % 0x10000 == token as int % 0x10000,
        (token as int + 0x10000) / 0x10000 == token as int / 0x10000 + 1,
{
    assert(1u64 << 16u32 == 0x10000) by (bit_vector);
    assert((token as int + 0x10000) % 0x10000 == token as int % 0x10000 && (token as int + 0x10000) / 0x10000 == token as int / 0x10000 + 1) by (nonlinear_arith);
    assert(token as int + 0x10000 <= u64::MAX) by (nonlinear_arith)
        requires (token as int) / 0x10000 < 0xFFFF_FFFF_FFFF;
}

pub(crate) proof fn quarantined_bits()
    ensures
        crate::custody::STORAGE | crate::custody::DETACHED == 6u8,
{
    assert(2u8 | 4u8 == 6u8) by (bit_vector);
}

pub(crate) proof fn key_packs(start: u64, len: u64)
    requires
        start < 0x100_0000_0000,
        len <= 0xFF_FFFF,
    ensures
        (start | len << 40u32) as int == start as int + len as int * 0x100_0000_0000,
{
    assert(start | len << 40u32 == start + len * 0x100_0000_0000) by (bit_vector)
        requires start < 0x100_0000_0000u64, len <= 0xFF_FFFFu64;
}

pub(crate) proof fn key_unpacks(key: u64)
    ensures
        1u64 << 40u32 == 0x100_0000_0000u64,
        (key & 0xFF_FFFF_FFFFu64) as int == key as int % 0x100_0000_0000,
        (key >> 40u32) as int == key as int / 0x100_0000_0000,
{
    assert(1u64 << 40u32 == 0x100_0000_0000u64) by (bit_vector);
    assert(key & 0xFF_FFFF_FFFFu64 == key % 0x100_0000_0000u64) by (bit_vector);
    assert(key >> 40u32 == key / 0x100_0000_0000u64) by (bit_vector);
}

/// A key unpacks to the start and saturated length it packed, and key order is `(length, start)` order: the facts the run index's search relies on.
pub(crate) proof fn keys_round_trip_and_order(s1: int, l1: int, s2: int, l2: int)
    requires
        0 <= s1 < 0x100_0000_0000,
        0 <= s2 < 0x100_0000_0000,
        0 <= l1 <= 0xFF_FFFF,
        0 <= l2 <= 0xFF_FFFF,
    ensures
        (s1 + l1 * 0x100_0000_0000) % 0x100_0000_0000 == s1,
        (s1 + l1 * 0x100_0000_0000) / 0x100_0000_0000 == l1,
        (s1 + l1 * 0x100_0000_0000 < s2 + l2 * 0x100_0000_0000) <==> (l1 < l2 || (l1 == l2 && s1 < s2)),
{
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse(
        s1 + l1 * 0x100_0000_0000,
        0x100_0000_0000,
        l1,
        s1,
    );
    if l1 < l2 {
        assert(l1 * 0x100_0000_0000 + 0x100_0000_0000 <= l2 * 0x100_0000_0000) by (nonlinear_arith)
            requires l1 < l2;
    } else if l2 < l1 {
        assert(l2 * 0x100_0000_0000 + 0x100_0000_0000 <= l1 * 0x100_0000_0000) by (nonlinear_arith)
            requires l2 < l1;
    }
}


/// `ceil(p / c)`: the fewest `c`-byte windows that hold `p` bytes.
pub(crate) open spec fn ceiling(p: int, c: int) -> int {
    if p % c == 0 { p / c } else { p / c + 1 }
}

/// The record format's header of `p` payload bytes under `c`-byte windows:
/// the fixed fields and `ceil(p / c) + 1` table entries.
pub(crate) open spec fn header(p: int, c: int) -> int {
    108 + 4 * (ceiling(p, c) + 1)
}

/// A record of `p` payload bytes under `c`-byte windows: header and payload.
pub(crate) open spec fn record_len(p: int, c: int) -> int {
    header(p, c) + p
}

/// The quotient and remainder steps [`ceiling`] takes.
pub(crate) proof fn ceiling_steps(p: int, c: int)
    requires
        0 <= p,
        0 < c,
    ensures
        (p / c) * c <= p < (p / c) * c + c,
        ((p / c) * c < p) == (p % c != 0),
        p / c <= p,
        (p / c) * c < p ==> p / c < p,
{
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(p, c);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(p, c);
    assert((p / c) * c == c * (p / c)) by (nonlinear_arith);
    assert(p / c <= p) by (nonlinear_arith)
        requires
            (p / c) * c <= p,
            0 < c,
            0 <= p,
            0 <= p / c;
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(p, c);
    if (p / c) * c < p {
        assert(p / c < p) by (nonlinear_arith)
            requires
                (p / c) * c < p,
                0 < c,
                0 <= p / c;
    }
}

/// [`ceiling`] of 0 is 0, and a positive `p` needs one window more than the
/// whole windows before its last byte, a count at most `p`.
pub(crate) proof fn ceiling_below(p: int, c: int)
    requires
        0 <= p,
        0 < c,
    ensures
        p == 0 ==> ceiling(p, c) == 0,
        p > 0 ==> (p - 1) / c + 1 == ceiling(p, c) && (p - 1) / c < p,
{
    if p == 0 {
        assert(0 * c + 0 == 0) by (nonlinear_arith);
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse(0, c, 0, 0);
    } else {
        ceiling_bounds(p, c);
        let q = ceiling(p, c);
        assert(1 <= q) by (nonlinear_arith)
            requires
                q * c >= p,
                p > 0,
                0 <= q;
        let r = p - 1 - (q - 1) * c;
        assert(0 <= r < c) by (nonlinear_arith)
            requires
                (q - 1) * c < p,
                p <= q * c,
                r == p - 1 - (q - 1) * c;
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse(p - 1, c, q - 1, r);
        ceiling_steps(p - 1, c);
    }
}

/// [`ceiling`] is the least window count that holds `p` bytes.
pub(crate) proof fn ceiling_bounds(p: int, c: int)
    requires
        0 <= p,
        0 < c,
    ensures
        ceiling(p, c) * c >= p,
        ceiling(p, c) == 0 || (ceiling(p, c) - 1) * c < p,
        0 <= ceiling(p, c) <= p / c + 1,
        ceiling(p, c) <= p,
{
    ceiling_steps(p, c);
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(p, c);
    let q = p / c;
    assert((q + 1) * c == q * c + c) by (nonlinear_arith);
    assert(q * c - c == (q - 1) * c) by (nonlinear_arith);
    if p % c != 0 {
        assert(q < p) by (nonlinear_arith)
            requires
                q * c < p,
                0 < c,
                0 <= q;
    }
}

/// The window count that holds `x` bytes is the only `k` whose windows
/// end at or past `x` while one fewer ends before it.
pub(crate) proof fn ceiling_unique(x: int, c: int, k: int)
    requires
        0 <= x,
        0 < c,
        1 <= k,
        (k - 1) * c < x <= k * c,
    ensures
        k == ceiling(x, c),
{
    ceiling_bounds(x, c);
    let q = ceiling(x, c);
    assert(k == q) by (nonlinear_arith)
        requires
            (k - 1) * c < x <= k * c,
            q * c >= x,
            q == 0 || (q - 1) * c < x,
            0 <= q,
            1 <= k,
            0 < c;
}

/// A header under windows of at least one unit is at most `2^54 + 112` for every
/// `u64` payload and below `2^24` for every payload below `2^33`.
pub(crate) proof fn header_bounds(p: int, c: int)
    requires
        0 <= p < 0x1_0000_0000_0000_0000,
        4096 <= c,
    ensures
        112 <= header(p, c) <= 0x40_0000_0000_0070,
        p < 0x2_0000_0000 ==> header(p, c) < 0x100_0000,
{
    ceiling_bounds(p, c);
    vstd::arithmetic::div_mod::lemma_div_is_ordered_by_denominator(p, 4096, c);
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(p, c);
    vstd::arithmetic::div_mod::lemma_div_is_ordered(p, 0xFFFF_FFFF_FFFF_FFFF, 4096);
    assert(0xFFFF_FFFF_FFFF_FFFFint / 4096 == 0xF_FFFF_FFFF_FFFFint) by (compute);
    let q = ceiling(p, c);
    assert(q <= 0x10_0000_0000_0000);
    assert(header(p, c) == 112 + 4 * q);
    if p < 0x2_0000_0000 {
        vstd::arithmetic::div_mod::lemma_div_is_ordered(p, 0x1_FFFF_FFFF, 4096);
        assert(0x1_FFFF_FFFFint / 4096 == 0x1F_FFFFint) by (compute);
        assert(q <= 0x20_0000);
    }
}

/// A window of a positive `u32` multiple of 4096 bytes spans `1..2^20`
/// units, and is that many units.
pub(crate) proof fn unit_multiple(c: int)
    requires
        4096 <= c < 0x1_0000_0000,
        c % 4096 == 0,
    ensures
        1 <= c / 4096 < 0x10_0000,
        c == (c / 4096) * 4096,
{
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(c, 4096);
    vstd::arithmetic::div_mod::lemma_div_is_ordered(4096, c, 4096);
    vstd::arithmetic::div_mod::lemma_div_is_ordered(c, 0xFFFF_FFFF, 4096);
    assert(0xFFFF_FFFFint / 4096 == 0xF_FFFFint) by (compute);
}

/// `x >> 42` is `x / 2^42`.
pub(crate) proof fn shift_42_is_division(x: u64)
    ensures
        x >> 42u64 == x / 0x400_0000_0000,
{
    assert(x >> 42u64 == x / 0x400_0000_0000) by (bit_vector);
}

/// The multiply-shift window count: for a window of `w` units, `r =
/// ceil(2^42 / w)` and `n = floor((b + 4096 w - 1) / 4096)`, `floor(n * r /
/// 2^42)` is `ceil(b / (4096 w))` for every `b` below `2^33` (Lemire, Kaser
/// and Kurz 2019, Lemma 1 with `N = 22`, `L = 20`).
pub(crate) proof fn lemire_windows(b: int, w: int, r: int)
    requires
        0 <= b < 0x2_0000_0000,
        1 <= w < 0x10_0000,
        r * w >= 0x400_0000_0000,
        (r - 1) * w < 0x400_0000_0000,
    ensures
        ({
            let c = w * 4096;
            let n = (b + c - 1) / 4096;
            let q = (n * r) / 0x400_0000_0000;
            &&& b + c - 1 < 0x1_0000_0000_0000_0000
            &&& 0 <= n < 0x30_0000
            &&& 0 <= n * r < 0x1_0000_0000_0000_0000
            &&& q * c >= b
            &&& (q == 0 || (q - 1) * c < b)
        }),
{
    let s: int = 0x400_0000_0000;
    let c = w * 4096;
    let x = b + c - 1;
    let n = x / 4096;
    assert(0 <= x < 0x3_0000_0000) by (nonlinear_arith)
        requires
            0 <= b < 0x2_0000_0000,
            1 <= w < 0x10_0000,
            c == w * 4096,
            x == b + c - 1;
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(x, 4096);
    assert(n < 0x30_0000);
    // floor(n / w) is floor(x / c), the window count of b.
    vstd::arithmetic::div_mod::lemma_div_denominator(x, 4096, w);
    let q0 = n / w;
    assert(q0 == x / c);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(x, c);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(x, c);
    assert(q0 * c >= b && (q0 == 0 || (q0 - 1) * c < b)) by (nonlinear_arith)
        requires
            x == c * q0 + x % c,
            0 <= x % c < c,
            x == b + c - 1,
            0 <= b,
            0 < c,
            0 <= q0;
    // floor(n * r / 2^42) is floor(n / w).
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(n, w);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(n, w);
    let t = n % w;
    let e = r * w - s;
    assert(0 <= e < w) by (nonlinear_arith)
        requires
            r * w >= s,
            (r - 1) * w < s,
            e == r * w - s;
    assert(0 <= n * e < s) by (nonlinear_arith)
        requires
            0 <= n < 0x30_0000,
            0 <= e < w,
            w < 0x10_0000,
            s == 0x400_0000_0000;
    assert(q0 * s * w <= (n * r) * w < (q0 + 1) * s * w) by (nonlinear_arith)
        requires
            n == w * q0 + t,
            0 <= t < w,
            r * w == s + e,
            0 <= n * e < s,
            0 <= q0;
    assert(q0 * s <= n * r < (q0 + 1) * s) by (nonlinear_arith)
        requires
            q0 * s * w <= (n * r) * w < (q0 + 1) * s * w,
            0 < w;
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(n, w);
    assert(0 <= n * r) by (nonlinear_arith)
        requires
            0 <= n,
            0 <= q0 * s <= n * r;
    assert((n * r) / s == q0) by {
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(n * r, s);
        vstd::arithmetic::div_mod::lemma_mod_pos_bound(n * r, s);
        let m = (n * r) / s;
        assert(m == q0) by (nonlinear_arith)
            requires
                n * r == s * m + (n * r) % s,
                0 <= (n * r) % s < s,
                q0 * s <= n * r < (q0 + 1) * s,
                0 < s;
    }
    assert(r <= s) by (nonlinear_arith)
        requires
            (r - 1) * w < s,
            r * w >= s,
            0 < s,
            1 <= w;
    assert(n * r < 0x1_0000_0000_0000_0000) by (nonlinear_arith)
        requires
            0 <= n < 0x30_0000,
            r <= s,
            s == 0x400_0000_0000;
}

/// The facts [`extent_counts`] returns: its header, first window and count
/// from the header rule, a floor division and the last payload byte's
/// window.
pub(crate) proof fn extent_counts_hold(p: int, c: int, h: int, first: int)
    requires
        0 <= p < 0x2_0000_0000,
        4096 <= c < 0x1_0000_0000,
        h == header(p, c),
        first == h / c,
    ensures
        p > 0 ==> first <= (h + p - 1) / c,
        h + p < 0x1_0000_0000_0000_0000,
        ({
            let count = if p == 0 { 0 } else { (h + p - 1) / c - first + 1 };
        ({
            let entries = (h - 108) / 4;
            &&& h == 108 + 4 * entries
            &&& entries == ceiling(p, c) + 1
            &&& entries >= 1
            &&& (entries - 1) * c >= p
            &&& (entries == 1 || (entries - 2) * c < p)
            &&& first * c <= h < (first + 1) * c
            &&& 0 <= count <= entries
            &&& (count == 0) == (p == 0)
            &&& (count > 0 ==> (first + count - 1) * c < h + p <= (first + count) * c)
            &&& (count > 0 ==> count == ceiling(h + p, c) - first)
            &&& h < 0x1_0000_0000
        })
        }),
{
    let count = if p == 0 { 0 } else { (h + p - 1) / c - first + 1 };
    ceiling_bounds(p, c);
    header_bounds(p, c);
    let q = ceiling(p, c);
    assert((h - 108) / 4 == q + 1) by {
        vstd::arithmetic::div_mod::lemma_div_multiples_vanish(q + 1, 4);
        assert(4 * (q + 1) == h - 108);
    }
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(h, c);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(h, c);
    assert(first * c <= h < (first + 1) * c) by (nonlinear_arith)
        requires
            h == c * first + h % c,
            0 <= h % c < c;
    if p > 0 {
        let l = (h + p - 1) / c;
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(h + p - 1, c);
        vstd::arithmetic::div_mod::lemma_mod_pos_bound(h + p - 1, c);
        assert(l * c <= h + p - 1 < (l + 1) * c) by (nonlinear_arith)
            requires
                h + p - 1 == c * l + (h + p - 1) % c,
                0 <= (h + p - 1) % c < c;
        assert(first <= l) by (nonlinear_arith)
            requires
                first * c <= h,
                h <= h + p - 1 < (l + 1) * c,
                0 < c;
        assert(l - first <= q) by (nonlinear_arith)
            requires
                l * c <= h + p - 1,
                h < (first + 1) * c,
                p <= q * c,
                0 < c;
        assert((first + count - 1) * c < h + p <= (first + count) * c) by (nonlinear_arith)
            requires
                count == l - first + 1,
                l * c <= h + p - 1 < (l + 1) * c;
        ceiling_unique(h + p, c, first + count);
    }
}

/// A record length names its payload back: past the fixed part `112`, the
/// rest of a record of `p` payload bytes holds `p + 4e` bytes for `e =
/// ceil(p / c)`, and `ceil((p + 4e) / (c + 4))` is `e`.
pub(crate) proof fn payload_names(len: int, c: int)
    requires
        4096 <= c < 0x1_0000_0000,
    ensures
        forall|p: int| #![trigger record_len(p, c)]
            0 <= p && record_len(p, c) == len ==> {
                let e = ceiling(p, c);
                &&& len >= 112
                &&& len - 112 == p + 4 * e
                &&& ceiling(len - 112, c + 4) == e
            },
{
    assert forall|p: int| #![trigger record_len(p, c)]
        0 <= p && record_len(p, c) == len implies {
            let e = ceiling(p, c);
            &&& len >= 112
            &&& len - 112 == p + 4 * e
            &&& ceiling(len - 112, c + 4) == e
        } by {
        ceiling_bounds(p, c);
        let e = ceiling(p, c);
        let rest = p + 4 * e;
        let d = c + 4;
        ceiling_bounds(rest, d);
        let k = ceiling(rest, d);
        if e == 0 {
            assert(p == 0) by (nonlinear_arith)
                requires
                    e * c >= p,
                    e == 0,
                    0 <= p;
        } else {
            assert(rest <= e * d && (e - 1) * d < rest) by (nonlinear_arith)
                requires
                    rest == p + 4 * e,
                    d == c + 4,
                    p <= e * c,
                    (e - 1) * c < p,
                    1 <= e;
        }
        assert(k == e) by (nonlinear_arith)
            requires
                k * d >= rest,
                k == 0 || (k - 1) * d < rest,
                0 <= k,
                rest <= e * d,
                e == 0 || (e - 1) * d < rest,
                0 <= e,
                0 < d,
                0 <= rest;
    }
}

/// `ceil(rest / (c + 4))` entries take at most `rest` bytes of table plus
/// `c` bytes per entry, and their table bytes stay within `u64`.
pub(crate) proof fn entries_fit(rest: int, c: int)
    requires
        0 <= rest < 0x1_0000_0000_0000_0000,
        4096 <= c < 0x1_0000_0000,
    ensures
        4 * ceiling(rest, c + 4) < 0x1_0000_0000_0000_0000,
        rest >= 4 * ceiling(rest, c + 4) ==> rest - 4 * ceiling(rest, c + 4) <= ceiling(rest, c + 4) * c,
{
    let d = c + 4;
    ceiling_bounds(rest, d);
    let k = ceiling(rest, d);
    assert(4 * k < 0x1_0000_0000_0000_0000) by (nonlinear_arith)
        requires
            k == 0 || (k - 1) * d < rest,
            rest < 0x1_0000_0000_0000_0000,
            4100 <= d,
            0 <= k;
    assert(rest - 4 * k <= k * c) by (nonlinear_arith)
        requires
            k * d >= rest,
            d == c + 4;
}

/// A payload `rest - 4 * entries` for `entries = ceil(rest / (c + 4))` has a
/// header and payload no longer than the record, so the check's sum stays
/// within `u64`.
pub(crate) proof fn header_fits(p: int, c: int, entries: int)
    requires
        0 <= p,
        4096 <= c,
        0 <= entries,
        p <= entries * c,
    ensures
        ceiling(p, c) <= entries,
        header(p, c) <= 112 + 4 * entries,
{
    ceiling_bounds(p, c);
    let q = ceiling(p, c);
    if q > 0 {
        assert(q - 1 < entries) by (nonlinear_arith)
            requires
                (q - 1) * c < p,
                p <= entries * c,
                0 < c;
    }
}


/// A layout the record format derives: `p` payload bytes under `c`-byte
/// windows with header `h`, first window `fw` and `count` chunks, as
/// `arithmetic::extent_counts` ensures them.
pub(crate) open spec fn counted(c: int, p: int, h: int, fw: int, count: int) -> bool {
    let entries = (h - 108) / 4;
    &&& 4096 <= c < 0x1_0000_0000
    &&& 0 <= p < 0x2_0000_0000
    &&& h == 108 + 4 * entries
    &&& entries >= 1
    &&& (entries - 1) * c >= p
    &&& (entries == 1 || (entries - 2) * c < p)
    &&& 0 <= fw
    &&& fw * c <= h < (fw + 1) * c
    &&& 0 <= count <= entries
    &&& (count == 0) == (p == 0)
    &&& (count > 0 ==> (fw + count - 1) * c < h + p <= (fw + count) * c)
    &&& h < 0x1_0000_0000
}

/// `Command::chunks_end`: one past the last chunk whose window a command
/// ending at window `ew` reaches, at most the chunk count.
pub(crate) open spec fn chunks_end(ew: int, fw: int, count: int) -> int {
    let reached = if ew > fw { ew - fw } else { 0 };
    if reached < count { reached } else { count }
}

/// `Command::plan` and `Command::following`'s length: `windows` whole
/// windows from `offset`, ending early at the read's end `e`.
pub(crate) open spec fn command_len(windows: int, c: int, e: int, offset: int) -> int {
    if windows * c < e - offset { windows * c } else { e - offset }
}

/// A command of a read ending at `e`, reading `len` bytes from `offset`, up
/// to window `ew`, with chunks `first..end`, under a counted layout: the
/// facts every handoff needs.
pub(crate) open spec fn reads(
    c: int, p: int, h: int, fw: int, count: int, e: int,
    offset: int, len: int, ew: int, first: int, end: int,
) -> bool {
    &&& 0 <= offset < e
    &&& 0 <= len
    &&& offset + len <= e
    &&& offset + len == if ew * c < e { ew * c } else { e }
    &&& 0 <= first <= end <= count
    &&& fw + end <= ew
    &&& (first < end ==> offset <= (fw + first) * c)
}

/// The handoff of chunks `first..upto` of a command that [`reads`]: the
/// chunks' payload bytes `start..stop` (`RecordLayout::chunks`) lie in the
/// command's buffer at `h + start - offset .. h + stop - offset`
/// (`Command::in_buffer`), inside `0..len`, with no subtraction below zero.
pub(crate) proof fn hands_off(
    c: int, p: int, h: int, fw: int, count: int, e: int,
    offset: int, len: int, ew: int, first: int, end: int, upto: int,
)
    requires
        counted(c, p, h, fw, count),
        reads(c, p, h, fw, count, e, offset, len, ew, first, end),
        h + p <= e,
        first < upto <= end,
    ensures
        ({
            let lo = (fw + first) * c;
            let hi = (fw + upto) * c;
            let start = (if lo > h { lo } else { h }) - h;
            let stop = (if hi < h + p { hi } else { h + p }) - h;
            &&& (if hi < h + p { hi } else { h + p }) >= h
            &&& 0 <= start <= stop <= p
            &&& h + start >= offset
            &&& h + stop - offset <= len
            &&& offset + (h + start - offset) == h + start
        }),
{
    let lo = (fw + first) * c;
    let hi = (fw + upto) * c;
    assert(hi >= (fw + 1) * c && hi >= lo && (fw + count - 1) * c >= lo && (fw + end) * c >= hi)
        by (nonlinear_arith)
        requires
            0 <= first < upto <= end <= count,
            0 <= fw,
            0 < c,
            lo == (fw + first) * c,
            hi == (fw + upto) * c;
    assert(ew * c >= (fw + end) * c) by (nonlinear_arith)
        requires
            fw + end <= ew,
            0 < c;
}

/// The first command of a read: from the record start, `windows` whole
/// windows or to the read's end, holding the header (`h <= len`), its
/// chunks up to its end window.
pub(crate) proof fn first_reads(
    c: int, p: int, h: int, fw: int, count: int, e: int, windows: int,
)
    requires
        counted(c, p, h, fw, count),
        h + p <= e,
        0 < windows,
        h <= command_len(windows, c, e, 0),
    ensures
        reads(c, p, h, fw, count, e, 0, command_len(windows, c, e, 0), windows, 0, chunks_end(windows, fw, count)),
{
    assert(command_len(windows, c, e, 0) <= windows * c);
    assert(fw <= windows) by (nonlinear_arith)
        requires
            fw * c <= h,
            h <= windows * c,
            0 < c,
            0 <= fw;
    assert(0 < e) by (nonlinear_arith)
        requires
            108 <= h,
            h + p <= e,
            0 <= p;
}

/// A command planned at chunk `next` below the count: from window `fw +
/// next`, `windows` whole windows or to the read's end.
pub(crate) proof fn planned_reads(
    c: int, p: int, h: int, fw: int, count: int, e: int, windows: int, next: int,
)
    requires
        counted(c, p, h, fw, count),
        h + p <= e,
        0 < windows,
        0 <= next < count,
    ensures
        ({
            let offset = (fw + next) * c;
            &&& offset < e
            &&& reads(c, p, h, fw, count, e, offset, command_len(windows, c, e, offset), fw + next + windows, next,
                chunks_end(fw + next + windows, fw, count))
        }),
{
    let offset = (fw + next) * c;
    assert(offset < e) by (nonlinear_arith)
        requires
            offset == (fw + next) * c,
            next <= count - 1,
            (fw + count - 1) * c < h + p,
            h + p <= e,
            0 < c;
    assert(0 <= offset) by (nonlinear_arith)
        requires
            offset == (fw + next) * c,
            0 <= fw,
            0 <= next,
            0 < c;
    assert((fw + next + windows) * c == offset + windows * c) by (nonlinear_arith)
        requires
            offset == (fw + next) * c;
}

/// A command submitted ahead of one that [`reads`] and leaves the read's
/// end: from its end window, `windows` whole windows or to the read's end,
/// its first chunk the earlier command's end.
pub(crate) proof fn ahead_reads(
    c: int, p: int, h: int, fw: int, count: int, e: int, windows: int,
    offset: int, len: int, ew: int, first: int, end: int,
)
    requires
        counted(c, p, h, fw, count),
        reads(c, p, h, fw, count, e, offset, len, ew, first, end),
        len == command_len(windows, c, e, offset),
        ew * c == offset + windows * c,
        end == chunks_end(ew, fw, count),
        h + p <= e,
        0 < windows,
        offset + len < e,
    ensures
        ({
            let next = ew * c;
            &&& next < e
            &&& (ew + windows) * c == next + windows * c
            &&& reads(c, p, h, fw, count, e, next, command_len(windows, c, e, next), ew + windows, end,
                chunks_end(ew + windows, fw, count))
        }),
{
    assert(ew * c < e);
    assert((ew + windows) * c == ew * c + windows * c) by (nonlinear_arith);
    assert(ew * c >= (fw + end) * c) by (nonlinear_arith)
        requires
            fw + end <= ew,
            0 < c;
    if end < chunks_end(ew + windows, fw, count) {
        assert(fw + end <= ew);
        assert(chunks_end(ew + windows, fw, count) <= ew + windows - fw);
        // The earlier command ended short of the count, so its end is its
        // end window's chunk and the next command starts there.
        assert(end == ew - fw);
        assert((fw + end) * c == ew * c);
    }
}

/// Window indexes of a read shorter than `2^34` bytes, under windows of at
/// least one unit and commands of at most `2^32` bytes, stay below `2^23`,
/// so a command's `u32` end window never overflows.
pub(crate) proof fn windows_fit(c: int, e: int, window: int, windows: int)
    requires
        4096 <= c,
        0 <= window,
        window * c < e <= 0x4_0000_0000,
        0 <= windows,
        windows * c < 0x1_0000_0000,
    ensures
        window + windows < 0x80_0000,
{
    assert(window < 0x40_0000 && windows < 0x10_0000) by (nonlinear_arith)
        requires
            4096 <= c,
            0 <= window,
            window * c < 0x4_0000_0000,
            0 <= windows,
            windows * c < 0x1_0000_0000;
}

/// `ReadSpan::new` for a buffer of `windows * c` bytes holding the largest
/// header `header_max`: `limit / c` windows, and the first window end of
/// `header_max` within them; a counted header within `header_max` ends
/// inside them.
pub(crate) proof fn read_span(c: int, windows: int, header_max: int)
    requires
        4096 <= c,
        0 <= windows,
        windows * c < 0x1_0000_0000,
        0 <= header_max,
        (header_max / c + 1) * c <= windows * c,
    ensures
        (windows * c) / c == windows,
        0 < windows,
        header_max < windows * c,
{
    vstd::arithmetic::div_mod::lemma_div_multiples_vanish(windows, c);
    assert(c * windows == windows * c) by (nonlinear_arith);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(header_max, c);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(header_max, c);
    vstd::arithmetic::div_mod::lemma_div_pos_is_pos(header_max, c);
    assert(header_max < (header_max / c + 1) * c) by (nonlinear_arith)
        requires
            header_max == c * (header_max / c) + header_max % c,
            header_max % c < c;
    assert(0 < windows) by (nonlinear_arith)
        requires
            (header_max / c + 1) * c <= windows * c,
            0 <= header_max / c,
            0 < c;
}


/// The command a handoff reads, as `handed_off_chunks_lie_inside_the_command_buffer`
/// picks it: the first command (`pick` 0), the command planned at chunk
/// `next` (1), or the command submitted ahead of the first or that planned
/// one (2): its offset, end window and chunks `first..end`.
pub(crate) open spec fn command(
    c: int, fw: int, count: int, windows: int, next: int, pick: int, from_first: bool,
) -> (int, int, int, int) {
    let first_end = chunks_end(windows, fw, count);
    let planned_ew = fw + next + windows;
    let planned_end = chunks_end(planned_ew, fw, count);
    if pick == 0 {
        (0, windows, 0, first_end)
    } else if pick == 1 {
        ((fw + next) * c, planned_ew, next, planned_end)
    } else {
        let (ew, end) = if from_first { (windows, first_end) } else { (planned_ew, planned_end) };
        (ew * c, ew + windows, end, chunks_end(ew + windows, fw, count))
    }
}

/// The read path hands off chunks inside each command's buffer, for every
/// window length: under a counted layout of a verified header no longer
/// than the first command, a read ending at or past the record within its
/// units, and commands of `windows` whole windows that hold the largest
/// header, the first command, a command planned at any chunk and a command
/// submitted ahead of either, each hand off chunks `first..upto` as
/// exactly those chunks' payload bytes inside `0..len`, every command lies
/// inside the read and below the chunk count, and its end window fits a
/// `u32`. This is `handed_off_chunks_lie_inside_the_command_buffer` in
/// `storage::volume::read::verification` over every chunk length.
pub(crate) proof fn handoff(
    c: int, p: int, h: int, fw: int, count: int, e: int, windows: int, header_max: int,
    pick: int, next: int, from_first: bool, upto: int,
)
    requires
        counted(c, p, h, fw, count),
        c % 4096 == 0,
        0 <= header_max < 0x1_0000_0000,
        0 <= windows,
        windows * c < 0x1_0000_0000,
        (header_max / c + 1) * c <= windows * c,
        h + p <= e <= h + p + 4095,
        h <= command_len(windows, c, e, 0),
        0 <= pick <= 2,
        pick > 0 ==> 0 <= next < count,
        ({
            let (offset, _, _, _) = command(c, fw, count, windows, next, 1, from_first);
            let earlier = if from_first { 0 } else { offset };
            pick == 2 ==> earlier + command_len(windows, c, e, earlier) < e
        }),
        ({
            let (_, _, first, end) = command(c, fw, count, windows, next, pick, from_first);
            first < upto <= end
        }),
    ensures
        ({
            let (offset, ew, first, end) = command(c, fw, count, windows, next, pick, from_first);
            let len = command_len(windows, c, e, offset);
            let lo = (fw + first) * c;
            let hi = (fw + upto) * c;
            let start = (if lo > h { lo } else { h }) - h;
            let stop = (if hi < h + p { hi } else { h + p }) - h;
            &&& end <= count
            &&& 0 <= offset < e
            &&& offset + len <= e
            &&& 0 <= start <= stop <= p
            &&& h + start >= offset
            &&& h + stop - offset <= len
            &&& ew < 0x80_0000
        }),
{
    read_span(c, windows, header_max);
    assert(e <= 0x4_0000_0000);
    first_reads(c, p, h, fw, count, e, windows);
    windows_fit(c, e, 0, windows);
    if pick > 0 {
        planned_reads(c, p, h, fw, count, e, windows, next);
        windows_fit(c, e, fw + next, windows);
    }
    let (offset, ew, first, end) = command(c, fw, count, windows, next, pick, from_first);
    if pick == 2 {
        let (planned, planned_ew, planned_first, planned_end) = command(c, fw, count, windows, next, 1, from_first);
        let (earlier, pew, pfirst, pend) = if from_first {
            (0, windows, 0, chunks_end(windows, fw, count))
        } else {
            (planned, planned_ew, planned_first, planned_end)
        };
        assert(pew * c == earlier + windows * c) by (nonlinear_arith)
            requires
                from_first ==> pew == windows && earlier == 0,
                !from_first ==> pew == fw + next + windows && earlier == (fw + next) * c;
        ahead_reads(c, p, h, fw, count, e, windows, earlier, command_len(windows, c, e, earlier), pew, pfirst, pend);
        windows_fit(c, e, pew, windows);
    }
    hands_off(c, p, h, fw, count, e, offset, command_len(windows, c, e, offset), ew, first, end, upto);
}


/// The local count: a header of `q + 1` entries for `q = ceil(p / c)` ends
/// inside window 0, so the payload's last byte lies in window `q - 1` or
/// `q`, and the count is `q` plus whether the record passes `q` windows.
pub(crate) proof fn local_count_holds(p: int, c: int, h: int)
    requires
        4096 <= c < 0x1_0000_0000,
        0 <= p < 0x2_0000_0000,
        h == header(p, c),
        h < c,
    ensures
        ({
            let q = (h - 112) / 4;
            &&& q == ceiling(p, c)
            &&& 0 <= q * c < 0x1_0000_0000_0000_0000
            &&& h + p < 0x1_0000_0000_0000_0000
            &&& p > 0 ==> 1 <= q
            &&& ({
                let count = if p == 0 { 0 } else { q + if h + p > q * c { 1int } else { 0 } };
                &&& (count == 0) == (p == 0)
                &&& (count > 0 ==> (count - 1) * c < h + p <= count * c)
                &&& (count > 0 ==> count == ceiling(h + p, c))
            })
        }),
{
    ceiling_bounds(p, c);
    header_bounds(p, c);
    let q = ceiling(p, c);
    assert((h - 112) / 4 == q) by {
        vstd::arithmetic::div_mod::lemma_div_multiples_vanish(q, 4);
        assert(4 * q == h - 112);
    }
    assert(q <= 0x40_0000);
    assert(0 <= q * c < 0x1_0000_0000_0000_0000) by (nonlinear_arith)
        requires
            0 <= q <= 0x40_0000,
            0 < c < 0x1_0000_0000;
    if p > 0 {
        assert(1 <= q) by (nonlinear_arith)
            requires
                q * c >= p,
                p > 0,
                0 <= q;
        assert(h + p <= (q + 1) * c && (q - 1) * c < h + p) by (nonlinear_arith)
            requires
                p <= q * c,
                (q - 1) * c < p,
                0 <= h < c,
                1 <= q;
        let count = q + if h + p > q * c { 1int } else { 0 };
        assert((count - 1) * c < h + p <= count * c) by (nonlinear_arith)
            requires
                count == q + if h + p > q * c { 1int } else { 0 },
                h + p <= (q + 1) * c,
                (q - 1) * c < h + p,
                1 <= q;
        ceiling_unique(h + p, c, count);
    }
}

} // verus!
