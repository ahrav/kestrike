//! A case builds a [`support::Fixture`], a repository with a base and a head, and runs the tool through
//! the real runner `scripts/reproduce-test.py` with the stand-ins of [`standins`]. A case that runs
//! through [`support::Fixture::red_green`] relaunches this test executable in a role, which can set the
//! run's [`Facts`](kestrike_tools::red_green::run::Facts); one that runs through
//! [`support::Fixture::tool`] or [`support::Fixture::spawn_tool`] starts the built binary.
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
