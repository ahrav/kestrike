//! The dispatch report's completion samples. [`Recent`] keeps the longest
//! run of the newest entries pushed that holds at most [`RECENT`] entries
//! whose JSON encodings sum to at most [`RECENT_BYTES`], so a report list
//! stays bounded in entries and in bytes for any window length.

use serde::Serialize;

/// The most completions of each kind a report keeps, so no report list
/// grows with the window.
pub const RECENT: usize = 64;

/// The most bytes the JSON encodings of one list's entries sum to.
pub const RECENT_BYTES: usize = 512 << 10;

/// The newest entries pushed, oldest first, within [`RECENT`] entries and
/// [`RECENT_BYTES`] encoded bytes. An entry that alone exceeds the byte
/// budget leaves the list empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Recent<T> {
    entries: Vec<T>,
    /// The summed length of the entries' JSON encodings.
    #[serde(skip)]
    bytes: usize,
}

impl<T> Default for Recent<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            bytes: 0,
        }
    }
}

impl<T: Serialize> Recent<T> {
    /// Appends `value`, then drops the oldest entries until the list is
    /// within [`RECENT`] entries and [`RECENT_BYTES`] encoded bytes.
    pub(super) fn push(&mut self, value: T) {
        self.bytes += encoded(&value);
        self.entries.push(value);
        while self.entries.len() > RECENT || self.bytes > RECENT_BYTES {
            self.bytes -= encoded(&self.entries.remove(0));
        }
    }
}

/// The length of `value`'s compact JSON encoding, the form the report
/// prints.
fn encoded(value: &impl Serialize) -> usize {
    serde_json::to_vec(value)
        .expect("a report sample encodes")
        .len()
}

impl<T> IntoIterator for Recent<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Recent<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<T> std::ops::Deref for Recent<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::{RECENT, RECENT_BYTES, Recent};

    /// A string of `bytes - 2` characters, which encodes to `bytes` bytes.
    fn entry(tag: char, bytes: usize) -> String {
        tag.to_string().repeat(bytes - 2)
    }

    /// Entries that sum to the byte budget all stay; one byte more drops
    /// the oldest entries until the rest fit, and an entry over the whole
    /// budget leaves the list empty.
    #[test]
    fn entries_past_the_byte_budget_drop_the_oldest() {
        let quarter = RECENT_BYTES / 4;
        let mut list = Recent::default();
        for tag in ['a', 'b', 'c', 'd'] {
            list.push(entry(tag, quarter));
        }
        assert_eq!(list.len(), 4);
        list.push(entry('e', 3));
        let tags: Vec<_> = list.iter().map(|entry| &entry[..1]).collect();
        assert_eq!(tags, ["b", "c", "d", "e"]);
        list.push(entry('f', RECENT_BYTES + 1));
        assert!(list.is_empty());
    }

    /// Small entries keep the newest [`RECENT`], and the byte total follows
    /// every eviction, so the list refills after large entries leave it.
    #[test]
    fn small_entries_keep_the_newest_by_count() {
        let mut list = Recent::default();
        list.push(entry('a', RECENT_BYTES));
        for index in 0..=RECENT {
            list.push(index.to_string());
        }
        assert_eq!(list.len(), RECENT);
        assert_eq!(list[0], "1");
        assert_eq!(list[RECENT - 1], RECENT.to_string());
    }
}
