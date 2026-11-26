//! Feed coverage: the caller's advance of an inclusive feed position after every event at or below it reached [`Storage::invalidate`](super::Storage::invalidate) and returned `Ok`, and the retirement-epoch count of resident retirements whose registration has not ended.
//!
//! Invariants owned by this module:
//!
//! - Every resident retirement registers under the current retirement epoch in the shard hold that ends its mapping and ends that registration in the pool-gate hold that retires its slot, or for a parked retirement service leaves unretired in the gate hold that converts the park through `end_parked`, never at the park itself; a retirement that loses the capture mutex leaves the marker and the registration counted until a later service pass.
//! - BOUNDED: the epoch word and the applied position are fixed control words, a count at [`COUNT_LIMIT`] closes coverage admission instead of wrapping, and coverage refuses no invalidation.
//! - Neither word grants service or acknowledges an invalidation; no lookup, lease or admission decision reads them, and [`Invalidation`](super::Invalidation) stays the live removal.

mod advance;
mod epochs;
mod feed;
mod step;

pub use advance::{Advance, CoverageError};
pub(crate) use epochs::{exhausted, register, release};
pub(crate) use feed::FEED_LEN;
pub use feed::{FeedContract, FeedError};
pub(crate) use step::COUNT_LIMIT;
