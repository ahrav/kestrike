//! What a slot record's locator names: one direct extent, or a sequence
//! handle naming the arena block that holds an object's extent locators.
//!
//! A locator whose length is at most [`DIRECT_UNITS`] decodes unchanged as
//! that direct extent. A length of `DIRECT_UNITS + count`, for a count
//! of 2 through [`EXTENT_LIMIT`], tags a sequence handle: its start field
//! holds the block's granule index, below `2^32`, and its tail is zero.
//! Every other locator decodes to nothing, so a corrupt record fails closed.

use super::blocks::Block;
use super::extent::ExtentLocator;
pub(crate) use super::geometry::DIRECT_UNITS;
use super::geometry::EXTENT_LIMIT;

/// What a slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Held {
    /// One extent, the object's whole record.
    Direct(ExtentLocator),
    /// The object's `count` extents, listed in `block`.
    Sequence { block: Block, count: u32 },
}

impl Held {
    /// What `locator` names, or `None` when it is neither form.
    pub(crate) fn decode(locator: ExtentLocator) -> Option<Self> {
        let len = locator.len_units();
        if len <= DIRECT_UNITS {
            return Some(Self::Direct(locator));
        }
        let count = len - DIRECT_UNITS;
        let block = u32::try_from(locator.start_unit()).ok()?;
        // The rebuilt handle has a zero tail, so equality proves the tail zero.
        let tagged = ExtentLocator::new(u64::from(block), len).ok()?;
        (count >= 2 && u64::from(count) <= EXTENT_LIMIT && tagged == locator).then_some(
            Self::Sequence {
                block: Block(block),
                count,
            },
        )
    }

    /// The extents the slot holds, one checkpoint row each.
    pub(crate) fn extents(self) -> u64 {
        match self {
            Self::Direct(_) => 1,
            Self::Sequence { count, .. } => u64::from(count),
        }
    }

    /// The locator a slot record stores for this value.
    pub(crate) fn locator(self) -> ExtentLocator {
        match self {
            Self::Direct(locator) => locator,
            Self::Sequence { block, count } => {
                ExtentLocator::new(u64::from(block.0), DIRECT_UNITS + count)
                    .expect("a block index and a tagged length fit their fields")
            }
        }
    }
}
