//! A fixed array of records addressed by `(slot, generation)` handles, shared by the device volume's operations and the network endpoints' requests.
//!
//! A slot's generation advances by one each time its record is removed, until it reaches the array's generation limit, so a handle to a removed record never names its successor.
//! A slot whose generation would pass the array's generation limit retires permanently; the array keeps its construction length.
//! Construction allocates the entries and the free list once; insert, lookup and removal allocate nothing.
//! Every slot at or above the array's high-water mark has always been free, so a scan over every record stops there.

pub(crate) struct Records<T> {
    entries: Box<[Entry<T>]>,
    /// Free slots, most recently freed last.
    free: Vec<u32>,
    /// A slot scan can stop after visiting `live` occupied slots.
    live: u32,
    /// One past the highest slot that has held a record.
    high_water: u32,
    /// The last generation a slot reaches before it retires.
    limit: u64,
}

#[cfg_attr(test, derive(Clone, Debug))]
struct Entry<T> {
    generation: u64,
    value: Option<T>,
}

impl<T> Records<T> {
    /// Bytes an array of `count` records allocates.
    pub(crate) fn metadata_bytes(count: u32) -> usize {
        count as usize * Self::entry_bytes()
    }

    /// Bytes each slot allocates: its entry and its free-list place.
    pub(crate) fn entry_bytes() -> usize {
        size_of::<Entry<T>>() + size_of::<u32>()
    }

    /// An array of `count` free slots whose generations run to `u64::MAX`.
    pub(crate) fn new(count: u32) -> Self {
        Self::with_generation_limit(count, u64::MAX)
    }

    /// An array of `count` free slots, each retiring once its generation would pass `limit`.
    pub(crate) fn with_generation_limit(count: u32, limit: u64) -> Self {
        Self {
            entries: (0..count)
                .map(|_| Entry {
                    generation: 0,
                    value: None,
                })
                .collect(),
            free: (0..count).rev().collect(),
            live: 0,
            high_water: 0,
            limit,
        }
    }

    /// Starts free slot `slot` at `generation`, at most the array's limit, so a test reaches the limit at its actual width.
    #[cfg(test)]
    pub(crate) fn start_slot_at(&mut self, slot: u32, generation: u64) {
        assert!(self.free.contains(&slot), "slot {slot} is not free");
        let entry = &mut self.entries[slot as usize];
        assert!(
            (entry.generation..=self.limit).contains(&generation),
            "generation {generation} rewinds the slot or passes the limit"
        );
        entry.generation = generation;
    }

    /// Whether [`insert`](Self::insert) would find a free slot.
    pub(crate) fn has_free(&self) -> bool {
        !self.free.is_empty()
    }

    /// Stores `value` in a free slot and returns its handle, or hands `value` back when every slot is live or retired.
    #[inline]
    pub(crate) fn insert(&mut self, value: T) -> Result<(u32, u64), T> {
        let Some(slot) = self.free.pop() else {
            return Err(value);
        };
        let entry = &mut self.entries[slot as usize];
        entry.value = Some(value);
        self.live += 1;
        self.high_water = self.high_water.max(slot + 1);
        Ok((slot, entry.generation))
    }

    #[inline]
    pub(crate) fn get(&self, slot: u32, generation: u64) -> Option<&T> {
        let entry = self.entries.get(slot as usize)?;
        entry
            .value
            .as_ref()
            .filter(|_| entry.generation == generation)
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, slot: u32, generation: u64) -> Option<&mut T> {
        let (current, value) = self.slot_mut(slot)?;
        (current == generation).then_some(value)
    }

    /// The generation of the live record in `slot`, if one is there.
    #[inline]
    pub(crate) fn generation_of(&self, slot: u32) -> Option<u64> {
        let entry = self.entries.get(slot as usize)?;
        entry.value.as_ref().map(|_| entry.generation)
    }

    /// The live record in `slot` with its generation, whatever handle named it.
    #[inline]
    pub(crate) fn slot_mut(&mut self, slot: u32) -> Option<(u64, &mut T)> {
        let entry = self.entries.get_mut(slot as usize)?;
        let generation = entry.generation;
        entry.value.as_mut().map(|value| (generation, value))
    }

    /// `remove` drops the record in `slot` in place, if present, and invalidates its handles.
    /// The slot returns to the free list if its generation can advance; otherwise, the slot retires.
    #[inline]
    pub(crate) fn remove(&mut self, slot: u32) {
        let entry = &mut self.entries[slot as usize];
        if entry.value.is_some() {
            entry.value = None;
            self.vacate(slot);
        }
    }

    /// Removes the record a `(slot, generation)` handle names, as [`remove`](Self::remove) does, and returns it; a stale handle removes nothing.
    #[inline]
    pub(crate) fn take(&mut self, slot: u32, generation: u64) -> Option<T> {
        let entry = self.entries.get_mut(slot as usize)?;
        if entry.generation != generation {
            return None;
        }
        let value = entry.value.take()?;
        self.vacate(slot);
        Some(value)
    }

    /// Reads the record a `(slot, generation)` handle names through `read`, then drops it in place as [`remove`](Self::remove) does; a stale handle reads and drops nothing.
    #[inline]
    pub(crate) fn drop_with<R>(
        &mut self,
        slot: u32,
        generation: u64,
        read: impl FnOnce(&T) -> R,
    ) -> Option<R> {
        let entry = self.entries.get_mut(slot as usize)?;
        if entry.generation != generation {
            return None;
        }
        let read = read(entry.value.as_ref()?);
        entry.value = None;
        self.vacate(slot);
        Some(read)
    }

    /// Advances an emptied slot's generation and frees it, or retires it at the limit.
    #[inline]
    fn vacate(&mut self, slot: u32) {
        self.live -= 1;
        let entry = &mut self.entries[slot as usize];
        if entry.generation < self.limit {
            entry.generation += 1;
            self.free.push(slot);
        }
    }

    pub(crate) fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Occupied slots.
    #[inline]
    pub(crate) fn live(&self) -> u32 {
        self.live
    }

    /// Slots whose generation is exhausted; they never hold a record again.
    pub(crate) fn retired(&self) -> u32 {
        self.len() - self.live - self.free.len() as u32
    }

    /// One past the highest slot that has held a record; every slot from here on has always been free.
    #[inline]
    pub(crate) fn high_water(&self) -> u32 {
        self.high_water
    }
}

/// A copy with the free list's order and capacity, so the copy's insert and
/// removal allocate nothing either; a copy whose allocator returned more
/// capacity panics.
#[cfg(test)]
impl<T: Clone> Clone for Records<T> {
    fn clone(&self) -> Self {
        let Self {
            entries,
            free,
            live,
            high_water,
            limit,
        } = self;
        let mut copy = Vec::with_capacity(free.capacity());
        copy.extend_from_slice(free);
        assert_eq!(copy.capacity(), free.capacity(), "the copy's free list");
        Self {
            entries: entries.clone(),
            free: copy,
            live: *live,
            high_water: *high_water,
            limit: *limit,
        }
    }
}

/// Every field, the free list's capacity included.
#[cfg(test)]
impl<T: std::fmt::Debug> std::fmt::Debug for Records<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            entries,
            free,
            live,
            high_water,
            limit,
        } = self;
        f.debug_struct("Records")
            .field("entries", entries)
            .field("free", free)
            .field("free_capacity", &free.capacity())
            .field("live", live)
            .field("high_water", high_water)
            .field("limit", limit)
            .finish()
    }
}
