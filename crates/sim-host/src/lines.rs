//! A running count of the complete lines of one append-only list, such as
//! a root's `suspects.jsonl`, read in bounded steps. A [`Lines`] counter
//! belongs to one list whose counted prefix, the bytes through the last
//! counted newline, stays as it is. The list may grow, and its uncounted
//! tail after the last newline may be rewritten. Replacing or rewriting the
//! counted prefix needs a fresh counter: the counter resets only when the
//! list is shorter than that prefix, and it detects no other change there.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::SystemTime;

/// The bytes one [`Lines::scan`] call reads at most.
pub const BUDGET: u64 = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lines {
    offset: u64,
    scanned: u64,
    count: u64,
    tail: Option<(u64, Option<SystemTime>)>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Count {
    /// The newline-terminated lines counted so far; an unterminated final
    /// record is not one.
    pub lines: u64,
    /// Whether this call read to the length it observed. It is false when
    /// the budget stopped the read first, and true with an unterminated
    /// final record. Bytes appended after the observation are not covered.
    pub complete: bool,
}

impl Lines {
    /// Reads at most `budget` bytes of `path` past what earlier calls read
    /// and returns the count. An absent list counts 0 and is complete; a
    /// symlink at `path` is an error, as for every reader of a root. A
    /// list shorter than the counted prefix resets the counter. The
    /// uncounted tail is read again when the list's length or modification
    /// time differs from the last call's.
    pub fn scan(&mut self, path: &Path, budget: u64) -> io::Result<Count> {
        let Some(mut list) = crate::file::open_plain(path)? else {
            *self = Self::default();
            return Ok(Count {
                lines: 0,
                complete: true,
            });
        };
        let meta = list.metadata()?;
        let length = meta.len();
        let stamp = (length, meta.modified().ok());
        if length < self.offset {
            *self = Self::default();
        } else if self.scanned > self.offset && self.tail != Some(stamp) {
            self.scanned = self.offset;
        }
        let end = length.min(self.scanned.saturating_add(budget));
        if self.scanned < end {
            list.seek(SeekFrom::Start(self.scanned))?;
            let mut chunk = vec![0u8; 64 << 10];
            while self.scanned < end {
                let want = usize::try_from(end - self.scanned)
                    .unwrap_or(usize::MAX)
                    .min(chunk.len());
                let read = list.read(&mut chunk[..want])?;
                if read == 0 {
                    break;
                }
                for (index, byte) in chunk[..read].iter().enumerate() {
                    if *byte == b'\n' {
                        self.count += 1;
                        self.offset = self.scanned + index as u64 + 1;
                    }
                }
                self.scanned += read as u64;
            }
        }
        self.tail = (self.scanned > self.offset).then_some(stamp);
        Ok(Count {
            lines: self.count,
            complete: self.scanned >= length,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use super::{Count, Lines};

    fn count(lines: u64, complete: bool) -> Count {
        Count { lines, complete }
    }

    fn rewrite(path: &Path, text: &str, age: u64) {
        fs::write(path, text).expect("the list is written");
        fs::File::options()
            .write(true)
            .open(path)
            .expect("the list")
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(age))
            .expect("its time");
    }

    fn newlines(path: &Path) -> u64 {
        fs::read(path)
            .expect("the list")
            .iter()
            .filter(|byte| **byte == b'\n')
            .count() as u64
    }

    #[test]
    fn only_complete_lines_count_and_no_byte_is_read_twice() {
        let dir = crate::file::scratch("lines");
        let path = dir.join("suspects.jsonl");
        let mut lines = Lines::default();
        assert_eq!(lines.scan(&path, 1 << 20).expect("absent"), count(0, true));
        fs::write(&path, "a\nb\ntorn").expect("a list with a torn tail");
        assert_eq!(lines.scan(&path, 1 << 20).expect("a scan"), count(2, true));
        assert_eq!(lines.scanned, 8, "the torn tail is scanned once");
        assert_eq!(lines.scan(&path, 1 << 20).expect("a scan"), count(2, true));
        assert_eq!(lines.scanned, 8, "an unchanged tail is not read again");
        let mut list = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("the list");
        list.write_all(b"\n").expect("the tail ends");
        assert_eq!(lines.scan(&path, 1 << 20).expect("a scan"), count(3, true));
        fs::write(&path, "a\n").expect("a shorter list");
        assert_eq!(lines.scan(&path, 1 << 20).expect("a scan"), count(1, true));
        fs::write(&path, "x\n".repeat(10)).expect("ten lines");
        let mut lines = Lines::default();
        assert_eq!(lines.scan(&path, 7).expect("a scan"), count(3, false));
        assert_eq!(lines.scan(&path, 7).expect("a scan"), count(7, false));
        assert_eq!(lines.scan(&path, 7).expect("a scan"), count(10, true));
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_linked_or_dangling_list_is_refused_and_an_absent_one_counts_0() {
        let dir = crate::file::scratch("lines-link");
        let target = dir.join("target");
        fs::write(&target, "a\nb\n").expect("a list outside the root");
        let list = dir.join("suspects.jsonl");
        std::os::unix::fs::symlink(&target, &list).expect("a link");
        assert!(
            Lines::default().scan(&list, super::BUDGET).is_err(),
            "a link"
        );
        fs::remove_file(&list).expect("the link");
        std::os::unix::fs::symlink(dir.join("absent"), &list).expect("a dangling link");
        assert!(
            Lines::default().scan(&list, super::BUDGET).is_err(),
            "a dangling link"
        );
        fs::remove_file(&list).expect("the link");
        assert_eq!(
            Lines::default()
                .scan(&list, super::BUDGET)
                .expect("an absent list"),
            count(0, true)
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_replaced_torn_tail_is_counted_again() {
        let dir = crate::file::scratch("lines-tail");
        let path = dir.join("suspects.jsonl");
        for replacement in ["a\nb\nc\n", "a\nb\nx\ny\n", "a\nb\nx\ny\nz\nw\n"] {
            let mut lines = Lines::default();
            rewrite(&path, "a\nb\ntorn", 100);
            assert_eq!(lines.scan(&path, 1 << 20).expect("a scan"), count(2, true));
            rewrite(&path, replacement, 200);
            let counted = lines.scan(&path, 1 << 20).expect("a scan");
            assert_eq!(counted, count(newlines(&path), true), "{replacement:?}");
            let mut list = fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("the list");
            list.write_all(b"q\n").expect("an appended line");
            let counted = lines.scan(&path, 1 << 20).expect("a scan");
            assert_eq!(counted, count(newlines(&path), true), "{replacement:?}");
        }
        assert!(
            Lines::default().scan(&dir, 1 << 20).is_err(),
            "a directory is refused"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
