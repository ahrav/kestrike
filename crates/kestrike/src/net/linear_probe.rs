//! Linear probing over the open-addressing tables that place a fixed set of entries once.
//!
//! - A table of [`table_len`] slots is a power of two in length and at least
//!   twice the count it places, so it keeps a vacant slot and every probe ends.
//! - An entry takes the first vacant slot in probe order from its hash, and
//!   occupied slots keep their entries, so a probe from that hash reaches the
//!   entry before it reaches a vacant slot.

/// Slots in a table for `count` entries: a power of two at least twice their count, and below four times a nonzero count, which leaves at least half the slots vacant.
pub(crate) fn table_len(count: usize) -> usize {
    (2 * count).next_power_of_two()
}

/// The slot hash uses bits [32, 64) of the 32-bit key's product with ⌊2^64/φ⌋; a table mask keeps the hash's low bits.
#[inline]
pub(crate) fn spread(key: u32) -> usize {
    (u64::from(key).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize
}

/// `probe` scans `table` linearly from `hash` and returns `Ok(slot)` for the first occupant that `matches`.
///
/// `table` is a power of two in length and holds a vacant slot, which ends the probe.
///
/// # Errors
///
/// `Err(slot)` names the first vacant slot, where the caller places an entry with hash `hash`.
#[inline(always)]
pub(crate) fn probe<T: Copy>(
    table: &[T],
    hash: usize,
    vacant: impl Fn(T) -> bool,
    matches: impl Fn(T) -> bool,
) -> Result<usize, usize> {
    probe_by(table, hash, |&occupant| occupant, vacant, matches)
}

/// [`probe`] over `read(&table[slot])`, with the same table preconditions. When slots only fill and `read` is an atomic
/// load, a probe that races a fill meets that slot vacant or holding its final entry.
///
/// # Errors
///
/// As [`probe`].
#[inline(always)]
pub(crate) fn probe_by<T, K: Copy>(
    table: &[T],
    hash: usize,
    read: impl Fn(&T) -> K,
    vacant: impl Fn(K) -> bool,
    matches: impl Fn(K) -> bool,
) -> Result<usize, usize> {
    let mask = table.len() - 1;
    let mut slot = hash & mask;
    loop {
        let occupant = read(&table[slot]);
        if vacant(occupant) {
            return Err(slot);
        }
        if matches(occupant) {
            return Ok(slot);
        }
        slot = (slot + 1) & mask;
    }
}

/// `find` scans `table` in [`probe`]'s slot order and returns the first occupant that `matches`, or `None` when it meets a vacant slot first.
///
/// `find` returns `None` for an empty `table`. A nonempty `table` must satisfy [`probe`]'s preconditions.
#[inline(always)]
pub(crate) fn find<T: Copy>(
    table: &[T],
    hash: usize,
    vacant: impl Fn(T) -> bool,
    matches: impl Fn(T) -> bool,
) -> Option<T> {
    let mask = table.len().wrapping_sub(1);
    let mut slot = hash & mask;
    // First-slot hits and vacancies bypass the probe loop. Keep the first-slot and loop checks identical: both test vacancy before a match.
    let first = *table.get(slot)?;
    if vacant(first) {
        return None;
    }
    if matches(first) {
        return Some(first);
    }
    loop {
        slot = (slot + 1) & mask;
        let seen = *table.get(slot)?;
        if vacant(seen) {
            return None;
        }
        if matches(seen) {
            return Some(seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{find, probe, spread, table_len};

    fn vacant(key: u32) -> bool {
        key == 0
    }

    /// [`find`] follows [`probe`]'s slot order so placed keys remain reachable. A constant hash forces collisions; starts near the table's end test wraparound, and starts above the mask test hash masking.
    #[test]
    fn find_returns_each_entry_probe_placed_and_none_for_an_absent_key() {
        for count in 0..=9u32 {
            let slots = table_len(count as usize);
            for start in 0..slots + 3 {
                let hashes: [&dyn Fn(u32) -> usize; 2] =
                    [&|_| start, &|key| spread(key).wrapping_add(start)];
                for hash in hashes {
                    let mut table = vec![0u32; slots];
                    for key in 1..=count {
                        let slot = probe(&table, hash(key), vacant, |seen| seen == key)
                            .expect_err("a key is placed once");
                        table[slot] = key;
                    }
                    for key in 1..=count {
                        let found = find(&table, hash(key), vacant, |seen| seen == key);
                        assert_eq!(found, Some(key), "{count} keys from slot {start}");
                    }
                    let absent = count + 1;
                    let found = find(&table, hash(absent), vacant, |seen| seen == absent);
                    assert_eq!(found, None, "{count} keys from slot {start}");
                }
            }
        }
    }

    #[test]
    fn find_in_a_table_of_no_slots_finds_nothing() {
        for hash in [0, 1, usize::MAX] {
            assert_eq!(find(&[], hash, vacant, |_| true), None, "hash {hash}");
        }
    }
}
