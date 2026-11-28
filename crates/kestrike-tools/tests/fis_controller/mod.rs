//! The cases of the FIS controller's library: the section's rules, the whole-file write, the custody
//! marker, the marks, the deadline rules, the fakes of the seam, and the named cases of the write's
//! and the poll's rules. Each expected value is the rule's on the row's input.

#![cfg(target_os = "linux")]

mod deadlines;
mod fakes;
mod marker;
mod marks;
mod section;
mod self_test;
mod whole;
