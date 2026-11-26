//! Kani proofs of the area views in `area`: [`DmaArea::split_at`](super::area::DmaArea::split_at) hands back two
//! adjacent views that together cover the view exactly, [`DmaArea::parts`](super::area::DmaArea::parts) tiles the
//! view in order with whole parts and a shorter remainder, and every refused operation returns the view unchanged
//! with the documented error.
//!
//! Bounds: each view lies in one 32 KiB allocation of eight `IO_UNIT`s, at a symbolic unit offset with a symbolic
//! length of one to eight units; split points and part lengths are symbolic `usize`s. The parts proof runs at an
//! unwinding bound of 10, above the eight parts a view of eight units yields at most.
//! Every view is built with `DmaArea::new` over an address derived from that one allocation's base, so it carries
//! the allocation's provenance, and nothing else reaches the allocation, which the proof never frees.

#[cfg(kani)]
mod verification {
    use std::alloc::{Layout, alloc_zeroed};
    use std::ptr::NonNull;

    use super::super::area::{AreaError, DmaArea};
    use super::super::config::IO_UNIT;

    /// Units in the allocation every view lies in.
    const UNITS: usize = 8;

    /// A view of a symbolic one to eight units at a symbolic unit offset inside one allocation of `UNITS` units,
    /// with the allocation's base.
    fn any_view() -> (DmaArea<'static>, NonNull<u8>) {
        let layout = Layout::from_size_align(UNITS * IO_UNIT, IO_UNIT).unwrap();
        // SAFETY: the layout has a non-zero size.
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let start: usize = kani::any();
        let units: usize = kani::any();
        kani::assume(start < UNITS && 0 < units && units <= UNITS - start);
        let offset = start * IO_UNIT;
        let len = units * IO_UNIT;
        // SAFETY: `offset + len` lies inside the allocation, which nothing else reaches and which is never freed.
        let addr = unsafe { base.add(offset) };
        // SAFETY: as above; the allocation is live, zeroed and exclusive for the rest of the proof.
        let view = unsafe { DmaArea::new(addr, offset, len) }.unwrap();
        (view, base)
    }

    /// Over one symbolic view and split point: the split succeeds exactly when the point is a positive unit
    /// multiple below the view's length, and then the head keeps the view's start and covers the point's bytes
    /// while the tail starts at the point and covers the rest; otherwise the view comes back unchanged, refused
    /// `Empty` for an empty half before `Misaligned` for an unaligned point.
    #[kani::proof]
    fn a_split_covers_the_view_exactly_or_returns_it_unchanged() {
        let (view, base) = any_view();
        let (addr, offset, len) = (view.addr(), view.offset(), view.len());
        assert_eq!(addr.as_ptr().addr(), base.as_ptr().addr() + offset);
        let at: usize = kani::any();
        match view.split_at(at) {
            Ok((head, tail)) => {
                kani::cover!(tail.len() > head.len());
                assert!(0 < at && at < len && at.is_multiple_of(IO_UNIT));
                assert_eq!((head.addr(), head.offset(), head.len()), (addr, offset, at));
                assert_eq!(tail.addr().as_ptr().addr(), addr.as_ptr().addr() + at);
                assert_eq!((tail.offset(), tail.len()), (offset + at, len - at));
                assert_eq!(head.offset() + head.len(), tail.offset());
                assert_eq!(tail.offset() + tail.len(), offset + len);
            }
            Err((back, error)) => {
                kani::cover!(error == AreaError::Empty);
                kani::cover!(error == AreaError::Misaligned);
                assert_eq!(
                    (back.addr(), back.offset(), back.len()),
                    (addr, offset, len)
                );
                if at == 0 || at >= len {
                    assert_eq!(error, AreaError::Empty);
                } else {
                    assert!(!at.is_multiple_of(IO_UNIT));
                    assert_eq!(error, AreaError::Misaligned);
                }
            }
        }
    }

    /// Over one symbolic view and part length: partitioning succeeds exactly when the length is a positive unit
    /// multiple no longer than the view; the parts then start at the view's start, follow one another without a
    /// gap, each covers the part length, and the remainder covers exactly the bytes after the last whole part, or
    /// is absent when the parts divide the view; a refused partition returns the view unchanged.
    #[kani::proof]
    #[kani::unwind(10)]
    fn parts_tile_the_view_in_order_and_leave_only_a_short_remainder() {
        let (view, _) = any_view();
        let (addr, offset, len) = (view.addr(), view.offset(), view.len());
        let part_len: usize = kani::any();
        match view.parts(part_len) {
            Ok(mut parts) => {
                assert!(0 < part_len && part_len <= len && part_len.is_multiple_of(IO_UNIT));
                let mut next = offset;
                let mut count = 0;
                for part in parts.by_ref() {
                    assert_eq!(part.offset(), next);
                    assert_eq!(
                        part.addr().as_ptr().addr(),
                        addr.as_ptr().addr() + (next - offset)
                    );
                    assert_eq!(part.len(), part_len);
                    next += part_len;
                    count += 1;
                }
                assert_eq!(count, len / part_len);
                match parts.remainder() {
                    Some(rest) => {
                        kani::cover!(true);
                        assert_eq!((rest.offset(), rest.len()), (next, len % part_len));
                        assert_eq!(
                            rest.addr().as_ptr().addr(),
                            addr.as_ptr().addr() + (next - offset)
                        );
                        assert!(rest.len() < part_len);
                    }
                    None => {
                        kani::cover!(count > 1);
                        assert_eq!(len % part_len, 0);
                        assert_eq!(next, offset + len);
                    }
                }
            }
            Err((back, error)) => {
                kani::cover!(error == AreaError::Empty);
                kani::cover!(error == AreaError::Misaligned);
                assert_eq!(
                    (back.addr(), back.offset(), back.len()),
                    (addr, offset, len)
                );
                if part_len == 0 || part_len > len {
                    assert_eq!(error, AreaError::Empty);
                } else {
                    assert!(!part_len.is_multiple_of(IO_UNIT));
                    assert_eq!(error, AreaError::Misaligned);
                }
            }
        }
    }
}
