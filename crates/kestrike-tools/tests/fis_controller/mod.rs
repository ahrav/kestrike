//! The cases of the FIS controller's library: the section's rules, the whole-file write, the custody
//! marker, the marks, the deadline rules, the fakes of the seam, and the two cases named for the
//! script's self-test. Each expected value was recorded from `scripts/fis-controller.py` on the same
//! input.

#![cfg(target_os = "linux")]

mod deadlines;
mod fakes;
mod marker;
mod marks;
mod section;
mod self_test;
mod whole;
