//! Typed tables placed inside a control mapping.
//!
//! A control mapping is laid out once, before it exists, as a sequence of
//! arrays through [`std::alloc::Layout::extend`]: each [`Field`] records the
//! checked, aligned, non-overlapping offset of one array and its element
//! count, and the finished extent is rounded up to a page multiple. After the
//! mapping is populated, control initialization sets every element of every
//! field exactly once; only then may a field be read. The zero fill from
//! [`Platform::map_inaccessible`] supplies an element's initial value when
//! [`is_plain_zero`] returns `true`; [`Field::init`] writes every other
//! element in place. Fields never move or grow, so a reference into one
//! stays valid for as long as the mapping is owned and no exclusive
//! reference aliases it.
//!
//! Only types without drop glue are placed here, so rollback and finalization have
//! nothing to destroy before they unmap.
//!
//! [`Platform::map_inaccessible`]: super::os::Platform::map_inaccessible

use std::alloc::Layout;
use std::any::Any;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;

use super::mapping::Mapping;

/// A control mapping's layout does not fit `isize::MAX`, or a table's index
/// type cannot address every element it must link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlLayoutOverflow;

/// Running layout of one control mapping.
pub(crate) struct ControlLayout {
    current: Layout,
}

/// Offset and element count of one typed array inside a control mapping.
///
/// Invariant: `offset` is a multiple of `align_of::<T>()` and
/// `offset + len * size_of::<T>()` lies within the extent of the mapping the
/// field was laid out for.
pub(crate) struct Field<T> {
    offset: usize,
    len: usize,
    marker: PhantomData<fn() -> T>,
}

// Manual impls: a field is a pair of integers whatever `T` is, so it copies
// and prints without requiring `T` to.
impl<T> Clone for Field<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Field<T> {}

impl<T> std::fmt::Debug for Field<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish()
    }
}

impl ControlLayout {
    pub(crate) fn new() -> Self {
        Self {
            current: Layout::new::<()>(),
        }
    }

    /// Appends an array of `len` values of `T` at the next aligned offset.
    ///
    /// Types with drop glue do not compile here: nothing destroys control
    /// values before unmap, so they must not need it.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if the array or the running total exceeds
    /// `isize::MAX`.
    pub(crate) fn field<T>(&mut self, len: usize) -> Result<Field<T>, ControlLayoutOverflow> {
        const { assert!(!std::mem::needs_drop::<T>()) };
        let array = Layout::array::<T>(len).map_err(|_| ControlLayoutOverflow)?;
        let (next, offset) = self
            .current
            .extend(array)
            .map_err(|_| ControlLayoutOverflow)?;
        self.current = next;
        Ok(Field {
            offset,
            len,
            marker: PhantomData,
        })
    }

    /// Moves the next field's offset up to a multiple of `align`, which is a
    /// power of two.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if the padded total exceeds `isize::MAX`.
    pub(crate) fn align_to(&mut self, align: usize) -> Result<(), ControlLayoutOverflow> {
        let size = self
            .current
            .size()
            .checked_next_multiple_of(align)
            .ok_or(ControlLayoutOverflow)?;
        self.current = Layout::from_size_align(size, self.current.align())
            .map_err(|_| ControlLayoutOverflow)?;
        Ok(())
    }

    /// Bytes laid out so far, before page rounding.
    pub(crate) fn size(&self) -> usize {
        self.current.size()
    }

    /// Total extent rounded up to a whole number of pages; at least one page.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if the rounded extent exceeds `isize::MAX`.
    pub(crate) fn extent(&self, page_size: usize) -> Result<usize, ControlLayoutOverflow> {
        let padded = self
            .current
            .align_to(page_size)
            .map_err(|_| ControlLayoutOverflow)?
            .pad_to_align()
            .size();
        Ok(padded.max(page_size))
    }
}

/// Whether `value` is one of the plain types the tables start at zero in bulk, a
/// `u16`, `u32`, `u64`, `AtomicU64` or `[u8; 32]`, and is zero. Such a value
/// has no padding, so it is all-zero bits. `false` for any other type, which
/// costs the caller only a store it could have skipped.
#[inline]
fn is_plain_zero<T: 'static>(value: &mut T) -> bool {
    let value: &mut dyn Any = value;
    if let Some(word) = value.downcast_mut::<u64>() {
        *word == 0
    } else if let Some(word) = value.downcast_mut::<AtomicU64>() {
        *word.get_mut() == 0
    } else if let Some(word) = value.downcast_mut::<u32>() {
        *word == 0
    } else if let Some(word) = value.downcast_mut::<u16>() {
        *word == 0
    } else if let Some(bytes) = value.downcast_mut::<[u8; 32]>() {
        // Byte by byte, so the test of a constant folds away with the loop
        // around it.
        bytes.iter().all(|byte| *byte == 0)
    } else {
        false
    }
}

impl<T> Field<T> {
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// # Safety
    ///
    /// `mapping` is the owned mapping this field was laid out for.
    #[inline]
    unsafe fn ptr(&self, mapping: &Mapping) -> *mut T {
        debug_assert!(mapping.is_owned());
        debug_assert!(self.offset + self.len * std::mem::size_of::<T>() <= mapping.len());
        // SAFETY: the field invariant bounds `offset` within the extent of the
        // mapping the caller guarantees this is, and that mapping is live.
        unsafe { mapping.base().as_ptr().add(self.offset).cast::<T>() }
    }

    /// Whether element `index` is all-zero bytes.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned, readable mapping this field was laid out for,
    /// `index < len`, and nothing has written the element since the mapping
    /// was acquired, so every byte of it is the platform's zero fill and no
    /// reference into it is live.
    unsafe fn holds_zero_fill(&self, mapping: &Mapping, index: usize) -> bool {
        // SAFETY: the caller guarantees the mapping, the bound and that the
        // element's bytes are initialized and unaliased.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.ptr(mapping).add(index).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        };
        bytes.iter().all(|byte| *byte == 0)
    }

    /// Sets element `i` to `values(i)` for every `i < len`. An element whose
    /// value [`is_plain_zero`] recognizes takes no store: the fresh mapping
    /// already holds it.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned, readable and writable mapping this field was
    /// laid out for, no reference into the field is live, and nothing has
    /// written the field since [`Platform::map_inaccessible`] returned the
    /// mapping, so it is zero-filled.
    ///
    /// [`Platform::map_inaccessible`]: super::os::Platform::map_inaccessible
    pub(crate) unsafe fn init(&self, mapping: &Mapping, mut values: impl FnMut(usize) -> T)
    where
        T: 'static,
    {
        // SAFETY: the caller guarantees `mapping` is the owned mapping this
        // field was laid out for.
        let ptr = unsafe { self.ptr(mapping) };
        for index in 0..self.len {
            let mut value = values(index);
            if is_plain_zero(&mut value) {
                // SAFETY: `index < len`, and the caller guarantees the
                // mapping and that the element is unwritten.
                debug_assert!(unsafe { self.holds_zero_fill(mapping, index) });
                continue;
            }
            // SAFETY: `index < len`, so the element lies inside the field; the
            // caller guarantees the mapping is writable and unaliased.
            unsafe { ptr.add(index).write(value) };
        }
    }

    /// Reads the field as a shared slice.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned mapping this field was laid out for,
    /// [`init`](Self::init) has completed for it, and no exclusive reference
    /// into the field is live.
    #[inline]
    pub(crate) unsafe fn as_slice<'m>(&self, mapping: &'m Mapping) -> &'m [T] {
        // SAFETY: the caller guarantees the owned mapping this field was laid
        // out for, initialization and no exclusive alias; the field invariant
        // gives alignment and bounds.
        unsafe { std::slice::from_raw_parts(self.ptr(mapping), self.len) }
    }

    /// Address of element `index`, for a cache hint. No bound is checked and
    /// nothing is read: the result is only an address, valid to pass to a
    /// prefetch and to nothing else.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned mapping this field was laid out for.
    #[inline]
    pub(crate) unsafe fn element_address(&self, mapping: &Mapping, index: usize) -> *const u8 {
        // SAFETY: the caller guarantees the owned mapping this field was laid
        // out for; the offset arithmetic wraps and the pointer is not read.
        unsafe { self.ptr(mapping) }
            .wrapping_add(index)
            .cast_const()
            .cast()
    }

    /// Raw pointer to element `index` for a holder whose exclusion covers
    /// that one element and no other.
    ///
    /// # Safety
    ///
    /// As for [`as_slice`](Self::as_slice), and `index < len`. Dereferencing
    /// the result additionally requires that no conflicting reference to the
    /// element is live: the caller holds the exclusion (an owner's uniqueness
    /// or the gate) that makes it the only access.
    #[inline(always)]
    pub(crate) unsafe fn element_ptr(&self, mapping: &Mapping, index: usize) -> NonNull<T> {
        debug_assert!(index < self.len);
        // SAFETY: as for `slice_ptr`; `index < len` keeps the element inside
        // the field, so the pointer is non-null and in bounds.
        unsafe { NonNull::new_unchecked(self.ptr(mapping).add(index)) }
    }

    /// Raw pointer to the whole field for a holder that has exclusive access
    /// and will form the `&mut [T]` itself.
    ///
    /// # Safety
    ///
    /// As for [`as_slice`](Self::as_slice). Dereferencing the result as
    /// `&mut` additionally requires that no other reference of any kind into
    /// the field is live: the caller holds the exclusion (a gate) that makes
    /// it the only access.
    #[inline]
    pub(crate) unsafe fn slice_ptr(&self, mapping: &Mapping) -> NonNull<[T]> {
        // SAFETY: the caller guarantees the owned mapping this field was laid
        // out for; the field invariant gives alignment and bounds and the
        // base is non-null.
        unsafe {
            NonNull::slice_from_raw_parts(NonNull::new_unchecked(self.ptr(mapping)), self.len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ControlLayout;

    const PAGE: usize = 4096;

    #[test]
    fn fields_are_aligned_disjoint_and_page_padded() {
        let mut layout = ControlLayout::new();
        assert_eq!(layout.extent(PAGE), Ok(PAGE));
        let bytes = layout.field::<u8>(3).unwrap();
        let words = layout.field::<u64>(2).unwrap();
        let more = layout.field::<u16>(1).unwrap();
        assert_eq!((bytes.offset, bytes.len), (0, 3));
        assert_eq!((words.offset, words.len), (8, 2));
        assert_eq!((more.offset, more.len), (24, 1));
        assert_eq!(layout.extent(PAGE), Ok(PAGE));

        let mut layout = ControlLayout::new();
        layout.field::<u8>(PAGE + 1).unwrap();
        assert_eq!(layout.extent(PAGE), Ok(2 * PAGE));

        let mut layout = ControlLayout::new();
        assert!(layout.field::<u64>(usize::MAX / 4).is_err());
    }

    #[test]
    fn align_to_pads_to_the_requested_alignment_only() {
        #[repr(align(64))]
        struct Line {
            _bytes: [u8; 64],
        }
        let mut layout = ControlLayout::new();
        layout.field::<Line>(1).unwrap();
        layout.field::<u8>(3).unwrap();
        assert_eq!(layout.size(), 67);
        layout.align_to(16).unwrap();
        assert_eq!(layout.size(), 80);
        let next = layout.field::<u8>(1).unwrap();
        assert_eq!(next.offset, 80);
        layout.align_to(64).unwrap();
        assert_eq!(layout.size(), 128);
    }
}
