//! A non-owning view of an arena-backed byte range.
//!
//! A view never holds a Rust reference to its bytes, because a device may write them while no host code looks.
//! Its start and length are multiples of [`IO_UNIT`], and its length is at least one unit.
//! Splitting and partitioning consume the view and hand back disjoint views; a refused operation returns the view unchanged.

use std::marker::PhantomData;
use std::ptr::NonNull;

use super::config::IO_UNIT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AreaError {
    /// A start, offset or length is not a multiple of [`IO_UNIT`].
    Misaligned,
    /// A zero length, or a split point or part length that leaves an empty view.
    Empty,
}

/// Exclusive access to `len` bytes at `addr`, for `'a`.
///
/// Invariants: `addr` is [`IO_UNIT`] aligned and carries the backing mapping's provenance.
/// `addr == backing base + offset`, and `offset + len` lies inside the backing.
/// `offset` and `len` are [`IO_UNIT`] multiples, and `len` is positive.
/// No other live view overlaps the range.
#[derive(Debug)]
pub(crate) struct DmaArea<'a> {
    addr: NonNull<u8>,
    offset: usize,
    len: usize,
    owner: PhantomData<&'a mut [u8]>,
}

impl<'a> DmaArea<'a> {
    /// Takes exclusive ownership of `len` bytes at `addr`, which lie `offset` bytes into the backing.
    ///
    /// # Safety
    ///
    /// `addr..addr + len` is live, initialized, readable and writable for `'a`, and lies `offset` bytes into one backing mapping whose provenance `addr` carries.
    /// `offset + len` fits the mapping, so `len <= isize::MAX` and the range does not wrap.
    /// No other view, handle or reference reaches any of it while the view lives.
    ///
    /// # Errors
    ///
    /// `Empty` if `len` is zero, then `Misaligned` if `addr`, `offset` or `len` is not a unit multiple.
    pub(crate) unsafe fn new(
        addr: NonNull<u8>,
        offset: usize,
        len: usize,
    ) -> Result<Self, AreaError> {
        if len == 0 {
            return Err(AreaError::Empty);
        }
        if !addr.as_ptr().addr().is_multiple_of(IO_UNIT)
            || !offset.is_multiple_of(IO_UNIT)
            || !len.is_multiple_of(IO_UNIT)
        {
            return Err(AreaError::Misaligned);
        }
        Ok(Self {
            addr,
            offset,
            len,
            owner: PhantomData,
        })
    }

    pub(crate) fn addr(&self) -> NonNull<u8> {
        self.addr
    }

    /// Byte offset of the view's start from the backing base.
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Splits into `[0, at)` and `[at, len)`.
    ///
    /// # Errors
    ///
    /// The view unchanged, with `Empty` if either half would be empty, then `Misaligned` if `at` is not a unit multiple.
    pub(crate) fn split_at(self, at: usize) -> Result<(Self, Self), (Self, AreaError)> {
        if at == 0 || at >= self.len {
            return Err((self, AreaError::Empty));
        }
        if !at.is_multiple_of(IO_UNIT) {
            return Err((self, AreaError::Misaligned));
        }
        // SAFETY: `at < len`, so the offset stays inside the view's range.
        let tail = unsafe { self.addr.add(at) };
        let tail = Self {
            addr: tail,
            offset: self.offset + at,
            len: self.len - at,
            owner: PhantomData,
        };
        Ok((Self { len: at, ..self }, tail))
    }

    /// Partitions into consecutive views of `part_len` bytes.
    /// Bytes after the last whole part come back from [`Parts::remainder`].
    ///
    /// # Errors
    ///
    /// The view unchanged, with `Empty` if `part_len` is zero or longer than the view, then `Misaligned` if it is not a unit multiple.
    pub(crate) fn parts(self, part_len: usize) -> Result<Parts<'a>, (Self, AreaError)> {
        if part_len == 0 || part_len > self.len {
            return Err((self, AreaError::Empty));
        }
        if !part_len.is_multiple_of(IO_UNIT) {
            return Err((self, AreaError::Misaligned));
        }
        Ok(Parts {
            rest: Some(self),
            part_len,
        })
    }
}

/// Consecutive `part_len`-byte views of one area, from its start.
#[derive(Debug)]
pub(crate) struct Parts<'a> {
    rest: Option<DmaArea<'a>>,
    part_len: usize,
}

impl<'a> Parts<'a> {
    /// After iteration ends: the bytes past the last whole part, or `None` when the parts divided the area exactly.
    pub(crate) fn remainder(self) -> Option<DmaArea<'a>> {
        self.rest.filter(|rest| rest.len < self.part_len)
    }
}

impl<'a> Iterator for Parts<'a> {
    type Item = DmaArea<'a>;

    fn next(&mut self) -> Option<DmaArea<'a>> {
        let rest = self.rest.take()?;
        if rest.len == self.part_len {
            return Some(rest);
        }
        match rest.split_at(self.part_len) {
            Ok((part, rest)) => {
                self.rest = Some(rest);
                Some(part)
            }
            Err((rest, _)) => {
                self.rest = Some(rest);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::ptr::NonNull;

    use super::{AreaError, DmaArea};

    const UNIT: usize = 4096;

    /// A zeroed, unit-aligned heap range standing in for backing memory, freed when dropped.
    struct Backing {
        base: NonNull<u8>,
        layout: Layout,
    }

    impl Backing {
        fn new(units: usize) -> Self {
            let layout = Layout::from_size_align(units * UNIT, UNIT).unwrap();
            // SAFETY: the layout has a non-zero size.
            let base = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            Self { base, layout }
        }

        fn area(&mut self) -> DmaArea<'_> {
            // SAFETY: the allocation is live and zeroed, and `&mut self` makes this view its only access.
            unsafe { DmaArea::new(self.base, 0, self.layout.size()) }.unwrap()
        }
    }

    impl Drop for Backing {
        fn drop(&mut self) {
            // SAFETY: allocated in `new` with this layout, and every view borrowed `self`.
            unsafe { dealloc(self.base.as_ptr(), self.layout) };
        }
    }

    /// Offset and length of a view, after checking its address is exactly `offset` bytes past `base`.
    fn span(base: NonNull<u8>, area: &DmaArea<'_>) -> (usize, usize) {
        assert_eq!(
            area.addr().as_ptr().addr(),
            base.as_ptr().addr() + area.offset()
        );
        (area.offset(), area.len())
    }

    #[test]
    fn construction_refuses_empty_and_misaligned_ranges() {
        let backing = Backing::new(2);
        let base = backing.base;
        // SAFETY: each view is dropped at once and none is read.
        unsafe {
            assert_eq!(DmaArea::new(base, 0, 0).unwrap_err(), AreaError::Empty);
            assert_eq!(
                DmaArea::new(base, 0, UNIT + 1).unwrap_err(),
                AreaError::Misaligned
            );
            assert_eq!(
                DmaArea::new(base, 512, UNIT).unwrap_err(),
                AreaError::Misaligned
            );
            assert_eq!(
                DmaArea::new(base.add(512), 0, UNIT).unwrap_err(),
                AreaError::Misaligned
            );
            assert_eq!(
                span(base, &DmaArea::new(base.add(UNIT), UNIT, UNIT).unwrap()),
                (UNIT, UNIT)
            );
        }
    }

    #[test]
    fn a_refused_split_returns_the_view_unchanged() {
        let mut backing = Backing::new(4);
        let base = backing.base;
        let mut area = backing.area();
        for (at, error) in [
            (0, AreaError::Empty),
            (4 * UNIT, AreaError::Empty),
            (5 * UNIT, AreaError::Empty),
            (UNIT + 8, AreaError::Misaligned),
        ] {
            let (back, refused) = area.split_at(at).unwrap_err();
            assert_eq!(refused, error, "{at}");
            assert_eq!(span(base, &back), (0, 4 * UNIT));
            area = back;
        }
        let (head, tail) = area.split_at(UNIT).unwrap();
        assert_eq!(
            (span(base, &head), span(base, &tail)),
            ((0, UNIT), (UNIT, 3 * UNIT))
        );
        let (mid, last) = tail.split_at(2 * UNIT).unwrap();
        assert_eq!(
            (span(base, &mid), span(base, &last)),
            ((UNIT, 2 * UNIT), (3 * UNIT, UNIT))
        );
    }

    #[test]
    fn parts_cover_the_view_exactly_or_return_the_remainder() {
        let mut backing = Backing::new(5);
        let base = backing.base;
        let area = backing.area();
        let area = match area.parts(0) {
            Err((area, AreaError::Empty)) => area,
            other => panic!("{other:?}"),
        };
        let area = match area.parts(6 * UNIT) {
            Err((area, AreaError::Empty)) => area,
            other => panic!("{other:?}"),
        };
        let area = match area.parts(UNIT + 1) {
            Err((area, AreaError::Misaligned)) => area,
            other => panic!("{other:?}"),
        };
        assert_eq!(span(base, &area), (0, 5 * UNIT));
        let mut parts = area.parts(2 * UNIT).unwrap();
        let spans: Vec<_> = parts.by_ref().map(|part| span(base, &part)).collect();
        assert_eq!(spans, [(0, 2 * UNIT), (2 * UNIT, 2 * UNIT)]);
        assert_eq!(
            parts.remainder().map(|rest| span(base, &rest)),
            Some((4 * UNIT, UNIT))
        );

        let mut backing = Backing::new(4);
        let base = backing.base;
        let mut parts = backing.area().parts(UNIT).unwrap();
        let spans: Vec<_> = parts.by_ref().map(|part| span(base, &part)).collect();
        assert_eq!(
            spans,
            [(0, UNIT), (UNIT, UNIT), (2 * UNIT, UNIT), (3 * UNIT, UNIT)]
        );
        assert!(parts.remainder().is_none());
    }
}
