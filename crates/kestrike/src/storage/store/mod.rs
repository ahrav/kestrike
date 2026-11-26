//! The off-volume store: the record keys, the conditional writes a store class offers, and the one client every
//! store access goes through.

mod client;
pub mod contract;
pub mod dynamo;
#[cfg(test)]
pub(crate) mod sim;
#[cfg(test)]
pub(crate) mod tally_tests;
mod watermark;
#[cfg(test)]
mod watermark_tests;

pub use client::{
    Alarm, Bumped, Client, Flipped, Outgoing, Read, RecordClass, StoreError, Tallied, Tally,
    Tracked, Transferred,
};
pub use contract::{ITEM_LIMIT, Item, Key, Outcome, Refusal, Store, Unavailable, Version, Write};
#[cfg(test)]
pub(crate) use watermark::LOAD_LIMIT;
pub use watermark::{FileLog, Regression, Watermark, WatermarkLog};
