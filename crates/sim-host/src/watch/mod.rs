//! `sim-host watch`: one loop over the bucket that keeps the last report
//! document, records each new failure identity, stores host events and
//! creates one summary per UTC day. [`cycle`] runs the loop, [`cache`]
//! holds root reads between cycles and [`decide`] chooses each cycle's
//! event writes.

mod cache;
mod cycle;
mod decide;

pub use cycle::run;
