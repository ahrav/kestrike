//! `free_runs_into` scans the free-unit bitmap and writes its maximal runs
//! of set bits into the caller's buffer as `(start, len)` in address order.
//! It allocates only when the buffer's capacity is below the number of
//! runs.

use super::ExtentAllocator;

impl ExtentAllocator<'_> {
    /// Clears `out`, then writes the bitmap's maximal free runs into it as
    /// `(start, len)` in address order.
    pub(crate) fn free_runs_into(&self, out: &mut Vec<(u64, u64)>) {
        out.clear();
        let mut extend = |unit: u64, len: u64| match out.last_mut() {
            Some((start, run)) if *start + *run == unit => *run += len,
            _ => out.push((unit, len)),
        };
        for (index, &word) in self.space[..self.root.base[0] as usize].iter().enumerate() {
            let base = index as u64 * u64::from(u64::BITS);
            let mut bit = 0;
            while bit < u64::BITS {
                let rest = word >> bit;
                if rest == 0 {
                    break;
                }
                let skip = rest.trailing_zeros();
                let ones = (rest >> skip).trailing_ones();
                extend(base + u64::from(bit + skip), u64::from(ones));
                bit += skip + ones;
            }
        }
    }
}
