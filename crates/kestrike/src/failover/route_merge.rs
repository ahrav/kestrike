//! RouteMonotonic: merge retains the largest `u64` order key and equal-key conflicts. `HighWater::merge` supplies
//! each tenure's `(g, a)` session as that key.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Incoming `(t, x)` merges into retained `(old_t, old_x, conflict)`, where `t` is a tenure's `(g, a)` order key and
/// `x` its host identifier. Returns `(key, identity, conflicted, admitted)`: key is the maximum, and admitted
/// accepts the incoming pair. Identity has meaning only outside Conflict; an existing conflict's placeholder
/// identity preserves refusal.
#[cfg_attr(verus_keep_ghost, verus_spec(out =>
    ensures
        out.0 >= old_t && out.0 >= t,
        t < old_t ==> out == (old_t, old_x, conflict, false),
        t > old_t ==> out == (t, x, false, true),
        t == old_t ==> out.0 == old_t && out.1 == old_x
            && out.2 == (conflict || x != old_x) && out.3 == !(conflict || x != old_x),
        conflict && t <= old_t ==> !out.3,
))]
pub fn merge_identity(
    old_t: u64,
    old_x: u128,
    conflict: bool,
    t: u64,
    x: u128,
) -> (u64, u128, bool, bool) {
    if t < old_t {
        (old_t, old_x, conflict, false)
    } else if t > old_t {
        (t, x, false, true)
    } else {
        let conflicted = conflict || x != old_x;
        (old_t, old_x, conflicted, !conflicted)
    }
}
