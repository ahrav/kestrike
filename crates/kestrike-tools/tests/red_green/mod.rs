//! A case builds a [`support::Fixture`], a repository with a base and a head, and runs the tool through
//! the real runner `scripts/reproduce-test.py` with the stand-ins of [`standins`]. A case that sets the
//! run's [`Facts`](kestrike_tools::red_green::run::Facts) relaunches this test executable in a role;
//! the other cases of [`signals`] and [`defects`] start the built binary.
#![cfg(target_os = "linux")]

mod defects;
mod directories;
mod git_steps;
mod lock;
mod proven;
mod reds;
mod rejected;
mod signals;
mod standins;
mod support;
mod trees;
