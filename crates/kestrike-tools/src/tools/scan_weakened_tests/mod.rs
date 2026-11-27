mod declarations;
mod digits;
mod hunks;
mod inventory;
mod patterns;
mod scan;

#[cfg(test)]
mod tests;

pub use scan::run;
use scan::{Failure, Shown};
