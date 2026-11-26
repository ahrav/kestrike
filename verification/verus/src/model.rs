//! Summary contracts use these bitmap predicates as their reference semantics.
//!
//! The bitmap predicate `b(u)` means unit `u` is free.

use vstd::prelude::*;

use crate::custody::{APPLICATION, DETACHED, Event, NIC, Next, RECEIVE, RETIRED, STORAGE};
use crate::partition::RawPartition;
use crate::summary::Summary;

verus! {

/// The six terms of a raw-byte ledger summed in unbounded integers.
pub(crate) open spec fn raw_sum(p: RawPartition) -> int {
    p.metadata + p.free + p.reserved + p.resident + p.retired + p.waste
}

pub(crate) open spec fn head(b: spec_fn(int) -> bool, lo: int, hi: int) -> int
    decreases hi - lo,
{
    if lo >= hi || !b(lo) {
        0
    } else {
        1 + head(b, lo + 1, hi)
    }
}

pub(crate) open spec fn tail(b: spec_fn(int) -> bool, lo: int, hi: int) -> int
    decreases hi - lo,
{
    if lo >= hi || !b(hi - 1) {
        0
    } else {
        1 + tail(b, lo, hi - 1)
    }
}

pub(crate) open spec fn longest(b: spec_fn(int) -> bool, lo: int, hi: int) -> int
    decreases hi - lo,
{
    if lo >= hi {
        0
    } else {
        vstd::math::max(longest(b, lo, hi - 1), tail(b, lo, hi))
    }
}

pub(crate) open spec fn summarizes(s: Summary, b: spec_fn(int) -> bool, lo: int, hi: int) -> bool {
    &&& s.start as int == head(b, lo, hi)
    &&& s.max as int == longest(b, lo, hi)
    &&& s.end as int == tail(b, lo, hi)
}

pub(crate) open spec fn joins(was: spec_fn(int) -> bool, now: spec_fn(int) -> bool, low: int, high: int) -> bool {
    &&& 0 <= low < high
    &&& forall|u: int| low <= u < high ==> #[trigger] now(u)
    &&& low == 0 || !now(low - 1)
    &&& !now(high)
    &&& forall|u: int| !(low <= u < high) ==> #[trigger] now(u) == was(u)
}

pub(crate) open spec fn splits(
    was: spec_fn(int) -> bool,
    now: spec_fn(int) -> bool,
    low: int,
    start: int,
    end: int,
    high: int,
) -> bool {
    &&& 0 <= low <= start < end <= high
    &&& forall|u: int| low <= u < high ==> #[trigger] was(u)
    &&& low == 0 || !was(low - 1)
    &&& !was(high)
    &&& forall|u: int| start <= u < end ==> !#[trigger] now(u)
    &&& forall|u: int| !(start <= u < end) ==> #[trigger] now(u) == was(u)
}

pub(crate) open spec fn legal_set(set: u8) -> bool {
    set == 0 || set == APPLICATION || set == STORAGE || set == STORAGE | DETACHED || set == RECEIVE
        || set == NIC || set == RETIRED
}

pub(crate) open spec fn legal_event(set: u8, nic: u16, event: Event) -> bool {
    match event {
        Event::Acquire | Event::Post => set == 0 && nic == 0,
        Event::Complete | Event::Unpost => set == RECEIVE && nic == 0,
        Event::IntoStorage => set == APPLICATION && nic == 0,
        Event::IntoBuffer | Event::Detach => set == STORAGE && nic == 0,
        Event::FreeDetached => set == STORAGE | DETACHED && nic == 0,
        Event::Drop => set == APPLICATION,
        Event::LastReturn => nic == 0 && (set == NIC || set == APPLICATION),
    }
}

pub(crate) open spec fn step(set: u8, nic: u16, event: Event) -> Next {
    match event {
        Event::Acquire | Event::Complete | Event::IntoBuffer => Next::Set(APPLICATION),
        Event::Post => Next::Set(RECEIVE),
        Event::IntoStorage => Next::Set(STORAGE),
        Event::Detach => Next::Set(STORAGE | DETACHED),
        Event::Unpost | Event::FreeDetached => Next::Free,
        Event::Drop => if nic > 0 { Next::Set(NIC) } else { Next::Free },
        Event::LastReturn => if set == APPLICATION { Next::Set(APPLICATION) } else { Next::Free },
    }
}

} // verus!
