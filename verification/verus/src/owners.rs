//! The ghost owner map and record table: each held unit's owner, and each slot's record of the extent its claim installed, kept together through the claims and returns that call the allocator's production plan decisions.
//!
//! A return reads its slot's record, as the table release reads the record's locator, so the units it frees follow from the bridge between records and owners.

use vstd::prelude::*;

verus! {

/// A held unit's owner: its object slot and incarnation, its phase and its record's payload.
pub struct Owner {
    pub slot: nat,
    pub incarnation: nat,
    pub phase: nat,
    pub payload: nat,
}

/// A slot's record: the extent `start..end` its claim installed and the owner that claim named.
pub struct Installed {
    pub start: int,
    pub end: int,
    pub owner: Owner,
}

/// The ghost state: the free set, the unit map and the record table.
pub struct Ghosts {
    pub free: spec_fn(int) -> bool,
    pub owned: spec_fn(int) -> Option<Owner>,
    pub records: spec_fn(nat) -> Option<Installed>,
}

/// Every unit of the volume is free or owned, never both, and nothing past the volume is either.
pub open spec fn consistent(volume: int, free: spec_fn(int) -> bool, owned: spec_fn(int) -> Option<Owner>) -> bool {
    &&& forall|u: int| 0 <= u < volume ==> (#[trigger] free(u) <==> owned(u) is None)
    &&& forall|u: int| #[trigger] free(u) ==> 0 <= u < volume
    &&& forall|u: int| #[trigger] owned(u) is Some ==> 0 <= u < volume
}

/// Each owned unit lies in its owner's slot record, and each record's units are all owned by the owner that record names.
pub open spec fn bridged(owned: spec_fn(int) -> Option<Owner>, records: spec_fn(nat) -> Option<Installed>) -> bool {
    &&& forall|u: int| #[trigger] owned(u) is Some ==> {
        let o = owned(u)->Some_0;
        &&& records(o.slot) is Some
        &&& records(o.slot)->Some_0.owner == o
        &&& records(o.slot)->Some_0.start <= u < records(o.slot)->Some_0.end
    }
    &&& forall|slot: nat| #[trigger] records(slot) is Some ==> {
        let r = records(slot)->Some_0;
        &&& r.owner.slot == slot
        &&& r.start < r.end
        &&& forall|u: int| r.start <= u < r.end ==> #[trigger] owned(u) == Some(r.owner)
    }
}

pub open spec fn valid(volume: int, g: Ghosts) -> bool {
    consistent(volume, g.free, g.owned) && bridged(g.owned, g.records)
}

/// `low..high` is a free run that no free unit extends on either side, the run an index entry names.
pub open spec fn maximal(volume: int, free: spec_fn(int) -> bool, low: int, high: int) -> bool {
    &&& low < high
    &&& forall|u: int| low <= u < high ==> #[trigger] free(u)
    &&& low == 0 || !free(low - 1)
    &&& high == volume || !free(high)
}

/// A claim by a free slot of `n` units at the start of the maximal free run `start..high` installs its record and owner on `start..start + n`, keeps every other owner and record, and the plan's remainder is the rest of the run, free and maximal.
pub fn claim(start: u64, n: u64, high: u64, Ghost(volume): Ghost<int>, Ghost(g): Ghost<Ghosts>, Ghost(owner): Ghost<Owner>) -> (out: (u64, u64, Ghost<Ghosts>))
    requires
        valid(volume, g),
        (g.records)(owner.slot) is None,
        0 < n,
        start + n <= high,
        forall|u: int| start <= u < high ==> #[trigger] (g.free)(u),
        high == volume || !(g.free)(high as int),
    ensures
        valid(volume, out.2@),
        (out.2@.records)(owner.slot) == Some(Installed { start: start as int, end: (start + n) as int, owner }),
        forall|slot: nat| slot != owner.slot ==> #[trigger] (out.2@.records)(slot) == (g.records)(slot),
        forall|u: int| start <= u < start + n ==> #[trigger] (out.2@.owned)(u) == Some(owner),
        forall|u: int| #[trigger] (g.owned)(u) is Some ==> (out.2@.owned)(u) == (g.owned)(u),
        out.0 == start + n,
        out.0 + out.1 == high,
        out.1 == 0 || maximal(volume, out.2@.free, out.0 as int, (out.0 + out.1) as int),
{
    let rest = crate::plan::remainder(start, n, high);
    let ghost lo = start as int;
    let ghost hi = (start + n) as int;
    let ghost record = Installed { start: lo, end: hi, owner };
    let ghost next = Ghosts {
        free: |u: int| (g.free)(u) && !(lo <= u < hi),
        owned: |u: int| if lo <= u < hi { Some(owner) } else { (g.owned)(u) },
        records: |slot: nat| if slot == owner.slot { Some(record) } else { (g.records)(slot) },
    };
    proof {
        assert forall|u: int| #[trigger] (g.owned)(u) is Some implies (next.owned)(u) == (g.owned)(u) by {
            if lo <= u < hi {
                assert((g.free)(u));
            }
        }
        assert forall|u: int| #[trigger] (next.owned)(u) is Some implies 0 <= u < volume by {
            if lo <= u < hi {
                assert((g.free)(u));
            }
        }
        assert forall|u: int| 0 <= u < volume implies (#[trigger] (next.free)(u) <==> (next.owned)(u) is None) by {}
        assert forall|u: int| #[trigger] (next.owned)(u) is Some implies {
            let o = (next.owned)(u)->Some_0;
            &&& (next.records)(o.slot) is Some
            &&& (next.records)(o.slot)->Some_0.owner == o
            &&& (next.records)(o.slot)->Some_0.start <= u < (next.records)(o.slot)->Some_0.end
        } by {
            if !(lo <= u < hi) {
                let o = (g.owned)(u)->Some_0;
                if o.slot == owner.slot {
                    assert((g.records)(o.slot) is Some);
                }
            }
        }
        assert forall|slot: nat| #[trigger] (next.records)(slot) is Some implies {
            let r = (next.records)(slot)->Some_0;
            &&& r.owner.slot == slot
            &&& r.start < r.end
            &&& forall|u: int| r.start <= u < r.end ==> #[trigger] (next.owned)(u) == Some(r.owner)
        } by {
            if slot != owner.slot {
                let r = (g.records)(slot)->Some_0;
                assert forall|u: int| r.start <= u < r.end implies #[trigger] (next.owned)(u) == Some(r.owner) by {
                    assert((g.owned)(u) == Some(r.owner));
                    if lo <= u < hi {
                        assert((g.free)(u));
                    }
                }
            }
        }
        assert(!(next.free)(hi - 1));
    }
    (rest.0, rest.1, Ghost(next))
}

/// A return through `slot`'s record, whose extent `start..end` the table release read from that record, frees exactly those units, every one of which that record's owner held, clears the record, and keeps every other owner and record; the plan's joined run is one maximal free run.
pub fn release(start: u64, end: u64, before: u64, after: u64, Ghost(volume): Ghost<int>, Ghost(g): Ghost<Ghosts>, Ghost(slot): Ghost<nat>) -> (out: (u64, u64, Ghost<Ghosts>))
    requires
        valid(volume, g),
        (g.records)(slot) is Some,
        (g.records)(slot)->Some_0.start == start,
        (g.records)(slot)->Some_0.end == end,
        before <= start,
        end + after <= u64::MAX,
        forall|u: int| start - before <= u < start ==> #[trigger] (g.free)(u),
        forall|u: int| end <= u < end + after ==> #[trigger] (g.free)(u),
        start - before == 0 || !(g.free)(start - before - 1),
        end + after == volume || !(g.free)(end + after),
    ensures
        valid(volume, out.2@),
        maximal(volume, out.2@.free, out.0 as int, out.1 as int),
        (out.2@.records)(slot) is None,
        forall|s: nat| s != slot ==> #[trigger] (out.2@.records)(s) == (g.records)(s),
        forall|u: int| !(start <= u < end) ==> #[trigger] (out.2@.owned)(u) == (g.owned)(u),
        forall|u: int| start <= u < end ==> #[trigger] (g.owned)(u) == Some((g.records)(slot)->Some_0.owner) && (out.2@.owned)(u) is None,
{
    proof {
        let r = (g.records)(slot)->Some_0;
        assert((g.owned)(start as int) == Some(r.owner));
    }
    let run = crate::plan::joined(start, end, before, after);
    let ghost lo = start as int;
    let ghost hi = end as int;
    let ghost mine = (g.records)(slot)->Some_0;
    let ghost next = Ghosts {
        free: |u: int| (g.free)(u) || (lo <= u < hi),
        owned: |u: int| if lo <= u < hi { None } else { (g.owned)(u) },
        records: |s: nat| if s == slot { None } else { (g.records)(s) },
    };
    proof {
        assert forall|u: int| #[trigger] (next.free)(u) implies 0 <= u < volume by {
            if lo <= u < hi {
                assert((g.owned)(u) == Some(mine.owner));
            }
        }
        assert forall|u: int| 0 <= u < volume implies (#[trigger] (next.free)(u) <==> (next.owned)(u) is None) by {
            if lo <= u < hi {
                assert((g.owned)(u) == Some(mine.owner));
            }
        }
        assert forall|u: int| #[trigger] (next.owned)(u) is Some implies {
            let o = (next.owned)(u)->Some_0;
            &&& (next.records)(o.slot) is Some
            &&& (next.records)(o.slot)->Some_0.owner == o
            &&& (next.records)(o.slot)->Some_0.start <= u < (next.records)(o.slot)->Some_0.end
        } by {
            let o = (g.owned)(u)->Some_0;
            if o.slot == slot {
                assert((g.records)(o.slot)->Some_0 == mine);
            }
        }
        assert forall|s: nat| #[trigger] (next.records)(s) is Some implies {
            let r = (next.records)(s)->Some_0;
            &&& r.owner.slot == s
            &&& r.start < r.end
            &&& forall|u: int| r.start <= u < r.end ==> #[trigger] (next.owned)(u) == Some(r.owner)
        } by {
            let r = (g.records)(s)->Some_0;
            assert forall|u: int| r.start <= u < r.end implies #[trigger] (next.owned)(u) == Some(r.owner) by {
                assert((g.owned)(u) == Some(r.owner));
                if lo <= u < hi {
                    assert((g.owned)(u) == Some(mine.owner));
                    assert(r.owner.slot == mine.owner.slot);
                }
            }
        }
        assert forall|u: int| run.0 <= u < run.1 implies #[trigger] (next.free)(u) by {
            if u < lo {
                assert((g.free)(u));
            } else if u >= hi {
                assert((g.free)(u));
            }
        }
        assert forall|u: int| lo <= u < hi implies #[trigger] (g.owned)(u) == Some(mine.owner) && (next.owned)(u) is None by {}
    }
    (run.0, run.1, Ghost(next))
}

/// A record names only units its own owner holds: a unit another slot owns lies in no range a return through this slot's record reads, so `return_extent` of one slot never frees another's unit.
pub proof fn records_name_only_their_owners_units(g: Ghosts, slot: nat, u: int)
    requires
        bridged(g.owned, g.records),
        (g.owned)(u) is Some,
        (g.owned)(u)->Some_0.slot != slot,
        (g.records)(slot) is Some,
    ensures
        !((g.records)(slot)->Some_0.start <= u < (g.records)(slot)->Some_0.end),
{
    let r = (g.records)(slot)->Some_0;
    if r.start <= u < r.end {
        assert((g.owned)(u) == Some(r.owner));
    }
}

} // verus!
