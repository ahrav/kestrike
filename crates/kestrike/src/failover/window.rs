//! Half-open serving windows anchored at certified Report submission.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(admitted =>
    ensures admitted <==> start <= now && now < end,
))]
pub fn contains(start: u64, end: u64, now: u64) -> bool {
    start <= now && now < end
}
