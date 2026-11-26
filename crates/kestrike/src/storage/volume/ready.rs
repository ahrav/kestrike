//! A set of read slots: one bit per slot of the read-operation array, with a constant-time emptiness check and slot-order iteration from a cursor.

pub(super) struct SlotSet {
    words: Box<[u64]>,
    /// The number of set bits in `words`, so [`any`](Self::any) answers in constant time at any read capacity.
    members: u32,
}

impl SlotSet {
    /// Bytes a set over `count` slots allocates.
    pub(super) fn metadata_bytes(count: u32) -> usize {
        count.div_ceil(64) as usize * size_of::<u64>()
    }

    pub(super) fn new(count: u32) -> Self {
        Self {
            words: vec![0; count.div_ceil(64) as usize].into_boxed_slice(),
            members: 0,
        }
    }

    #[inline]
    pub(super) fn set(&mut self, slot: u32, member: bool) {
        let (word, shift) = (&mut self.words[slot as usize / 64], slot % 64);
        let was = (*word >> shift) & 1;
        *word = (*word & !(1 << shift)) | (u64::from(member) << shift);
        // `members` includes the old bit, which guarantees `members >= was` before the subtraction.
        self.members = self.members - was as u32 + u32::from(member);
    }

    /// Whether any slot is a member.
    #[inline]
    pub(super) fn any(&self) -> bool {
        self.members != 0
    }

    #[cfg(test)]
    pub(super) fn members(&self) -> u32 {
        self.members
    }

    /// The lowest member in `from..end`; `end` is at most the slot count the set was built with.
    /// The `members` check makes an empty set's lookup cost independent of the slot count.
    #[inline]
    pub(super) fn next(&self, from: u32, end: u32) -> Option<u32> {
        if self.members == 0 {
            return None;
        }
        let mut index = from as usize / 64;
        let mut word = *self.words.get(index)? & (!0 << (from % 64));
        loop {
            if word != 0 {
                let slot = (index * 64) as u32 + word.trailing_zeros();
                return (slot < end).then_some(slot);
            }
            index += 1;
            if index * 64 >= end as usize {
                return None;
            }
            word = self.words[index];
        }
    }
}
