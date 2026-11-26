//! Lookup of a snapshot's jobs by id. The index stores a 32-bit id hash and
//! a 32-bit job index per job, and the snapshot keeps the ids. Entries are
//! sorted by hash, so a lookup is one binary search followed by an id
//! comparison for each job that shares the hash. A lookup returns exactly
//! the jobs whose id equals the one asked for, every duplicate included.

use crate::snapshot::Job;

#[derive(Debug, Default)]
pub(crate) struct IdIndex {
    entries: Vec<(u32, u32)>,
}

impl IdIndex {
    /// Indexes `jobs`. Job indices fit in `u32`, and the conversion panics
    /// otherwise: each parsed `Job` takes several hundred bytes, so 2^32
    /// jobs need over a terabyte of memory, which a snapshot exhausts well
    /// before reaching that count.
    pub(crate) fn new(jobs: &[Job]) -> Self {
        let mut entries: Vec<(u32, u32)> = jobs
            .iter()
            .enumerate()
            .map(|(index, job)| {
                let index = u32::try_from(index).expect("job indices fit in u32");
                (hash(&job.id), index)
            })
            .collect();
        entries.sort_unstable();
        Self { entries }
    }

    /// The indices in `jobs`, ascending, of the jobs whose id is `id`.
    /// `jobs` is the slice this index was built from.
    pub(crate) fn find<'a>(
        &'a self,
        jobs: &'a [Job],
        id: &'a str,
    ) -> impl Iterator<Item = usize> + 'a {
        let key = hash(id);
        let start = self.entries.partition_point(|&(hashed, _)| hashed < key);
        self.entries[start..]
            .iter()
            .take_while(move |&&(hashed, _)| hashed == key)
            .map(|&(_, index)| index as usize)
            .filter(move |&index| jobs[index].id == id)
    }

    /// The id of a job in `jobs` equal to `id`.
    pub(crate) fn get<'a>(&self, jobs: &'a [Job], id: &str) -> Option<&'a str> {
        self.find(jobs, id)
            .next()
            .map(|index| jobs[index].id.as_str())
    }
}

/// A word-at-a-time multiplicative hash, folded to 32 bits. Distinct ids
/// can share a hash; the id comparison in [`IdIndex::find`] separates them.
fn hash(id: &str) -> u32 {
    const MULTIPLIER: u64 = 0x9e37_79b9_7f4a_7c15;
    let bytes = id.as_bytes();
    let mut hash = bytes.len() as u64;
    let (words, rest) = bytes.as_chunks::<8>();
    for word in words {
        hash = (hash ^ u64::from_le_bytes(*word))
            .wrapping_mul(MULTIPLIER)
            .rotate_left(29);
    }
    let mut tail = [0u8; 8];
    tail[..rest.len()].copy_from_slice(rest);
    hash = (hash ^ u64::from_le_bytes(tail)).wrapping_mul(MULTIPLIER);
    (hash >> 32) as u32 ^ hash as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str) -> Job {
        Job {
            id: id.to_owned(),
            ..Job::default()
        }
    }

    /// Every job with the id is found, duplicates included; an id no job
    /// carries, a prefix of one or an extension of one finds nothing.
    #[test]
    fn find_returns_every_job_with_the_id_and_only_those() {
        let jobs = [job("a"), job("b"), job("a"), job("abcdefgh"), job("")];
        let index = IdIndex::new(&jobs);
        assert_eq!(index.find(&jobs, "a").collect::<Vec<_>>(), [0, 2]);
        assert_eq!(index.find(&jobs, "abcdefgh").collect::<Vec<_>>(), [3]);
        assert_eq!(index.find(&jobs, "").collect::<Vec<_>>(), [4]);
        assert_eq!(index.get(&jobs, "b"), Some("b"));
        for absent in ["c", "abcdefg", "abcdefghi", "A"] {
            assert_eq!(index.get(&jobs, absent), None, "{absent}");
        }
    }
}
