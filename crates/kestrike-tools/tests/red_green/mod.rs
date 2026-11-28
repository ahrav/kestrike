//! The cases of a red-green run that send it no signal. A case builds a [`support::Fixture`], a
//! repository with a base and a head, and runs the tool through the real runner `scripts/reproduce-test.py`
//! with the stand-ins of [`standins`]; the run is this test executable started again in a role, so the
//! handlers it installs and the facts a case sets stand in a process of the case's own.
#![cfg(target_os = "linux")]

mod directories;
mod git_steps;
mod lock;
mod proven;
mod reds;
mod rejected;
mod standins;
mod support;
mod trees;
