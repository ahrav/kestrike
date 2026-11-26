//! The zone reconciler service: the shell around `kestrike::failover::zone_loop` for one zone. It validates its
//! configuration ([`config`]) and the fleet directory file ([`directory`]), builds its AWS clients ([`aws`]), keeps
//! the store client's durable watermark in a locked state directory ([`state`]), and runs the loop ([`run`]) over
//! the zone's read sources ([`sources`]) until a stop signal ([`signal`]), publishing each tick's status
//! ([`status`]). The operator's guide is `docs/agents/reconciler.md`.
//!
//! STANDBY-GATE: the reconciler's standby, census, replacement and flip steps take a `StandbyGate` or an
//! `OperatorRelease`, whose constructors exist only in `kestrike`'s own test builds. [`run`] moves its
//! `Reconciler` into `ZoneLoop::new` and calls only `ZoneLoop::tick` and `ZoneLoop::deadline`, the survey makes
//! reads only, and the binary constructs the store table and the zone listings alone. Naming the gate's constructor
//! here fails to compile:
//!
//! ```compile_fail,E0599
//! let _ = kestrike::failover::reconcile::StandbyGate::qualified();
//! ```
//!
//! The gate's type is public, so the failure above comes from the constructor alone:
//!
//! ```
//! fn gated(_: Option<kestrike::failover::reconcile::StandbyGate>) {}
//! ```

pub mod aws;
pub mod cli;
pub mod config;
pub mod directory;
pub mod file;
pub mod run;
pub mod signal;
pub mod sources;
pub mod state;
pub mod status;

#[cfg(test)]
mod fixture;
