//! One acquired anonymous mapping: its original base, its full extent and
//! whether the kernel still holds it.
//!
//! A [`Mapping`] is released through the platform exactly once. Release moves
//! it to `Released` on success or `Retained` on kernel failure; both are
//! terminal, so no later call can unmap the same range twice or unmap a range
//! the kernel refused to give back. Only an explicit `release` unmaps: the
//! initialization transaction and the storage owner call it in their own
//! order and report each outcome.

use std::ptr::NonNull;

use super::os::{OsCode, Platform};

/// Which storage range a mapping backs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Engine-shared controls.
    Root,
    /// The volume's control tables.
    Control,
    /// The index's shard tables and reader scratch.
    Index,
    /// One device buffer arena.
    Buffers,
}

/// A mapping the kernel refused to release: still owned, still charged.
///
/// `base` is reported as an integer for operators and tests; nothing converts
/// it back into a pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedMapping {
    pub region: Region,
    pub base: usize,
    pub len: usize,
    pub code: OsCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Owned,
    Released,
    Retained(OsCode),
}

#[derive(Debug)]
pub(crate) struct Mapping {
    region: Region,
    base: NonNull<u8>,
    len: usize,
    state: State,
    /// Pages the post-population placement check covered without finding one
    /// outside the bound mask.
    pages_verified: usize,
}

impl Mapping {
    /// Takes ownership of `len` bytes at `base` as returned by
    /// [`Platform::map_inaccessible`] or [`Platform::map_hugepages`].
    pub(crate) fn owned(region: Region, base: NonNull<u8>, len: usize) -> Self {
        Self {
            region,
            base,
            len,
            state: State::Owned,
            pages_verified: 0,
        }
    }

    /// A zero-length range that was never mapped. Every platform call skips
    /// it and every accessor sees an empty extent.
    pub(crate) fn empty(region: Region) -> Self {
        Self {
            region,
            base: NonNull::dangling(),
            len: 0,
            state: State::Released,
            pages_verified: 0,
        }
    }

    /// Original base. Valid to dereference only while [`is_owned`](Self::is_owned).
    #[inline]
    pub(crate) fn base(&self) -> NonNull<u8> {
        self.base
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn is_owned(&self) -> bool {
        self.state == State::Owned
    }

    /// Pages the post-population placement check covered without finding one
    /// outside the bound mask; see [`PlacementReport`](super::owner::PlacementReport).
    pub(crate) fn pages_verified(&self) -> usize {
        self.pages_verified
    }

    pub(crate) fn set_pages_verified(&mut self, pages: usize) {
        self.pages_verified = pages;
    }

    pub(crate) fn retained(&self) -> Option<RetainedMapping> {
        match self.state {
            State::Retained(code) => Some(RetainedMapping {
                region: self.region,
                base: self.base.as_ptr() as usize,
                len: self.len,
                code,
            }),
            State::Owned | State::Released => None,
        }
    }

    /// Releases the whole mapping through `platform` if it is still owned.
    /// A mapping that was already released or retained is left untouched.
    ///
    /// # Safety
    ///
    /// No reference derived from [`base`](Self::base) may survive the call.
    ///
    /// # Errors
    ///
    /// The kernel's code when release fails; the mapping becomes `Retained`
    /// and stays charged.
    pub(crate) unsafe fn release<P: Platform>(&mut self, platform: &P) -> Result<(), OsCode> {
        if self.state != State::Owned {
            return Ok(());
        }
        // SAFETY: `base` and `len` are the original base and full extent of a
        // mapping this platform returned; the state check above proves it has
        // not been released, and the caller guarantees no surviving reference.
        match unsafe { platform.unmap(self.base, self.len) } {
            Ok(()) => {
                self.state = State::Released;
                Ok(())
            }
            Err(code) => {
                self.state = State::Retained(code);
                Err(code)
            }
        }
    }
}
