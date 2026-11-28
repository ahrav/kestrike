pub const NAME: &str = "scan-weakened-tests";

mod cases;
mod declarations;
mod digits;
mod failure;
mod finding;
mod hunks;
mod inventory;
mod patterns;
mod scan;
mod tree;

#[cfg(test)]
mod tests;

use failure::Failure;
use finding::{Change, Class, Finding, Shown};
pub use scan::{run, scan_range};
