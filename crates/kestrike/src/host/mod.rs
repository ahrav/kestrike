//! The host composition: the owner process that serves one attached cache volume through the failover sequences.
//! One owner process runs per attached volume. Each run of it, an incarnation, derives its role from the volume
//! record and the shard record ([`recover::role`]), acquires at most one tenure through the sequence that role
//! names, and ends through one [`Exit`]. A waiting standby runs one takeover per accepted nomination until one
//! acquires its tenure or ends the incarnation. [`inputs`] builds the values the sequences and the owner's poll take, and
//! computes the peers they bind.
//! [`fencer`] adapts any reservation-capable driver to the device halves of the restart, the fresh first acquisition
//! and the takeover before the volume attaches. [`recover::recover`] runs a restart or fresh role's sequence through
//! it, and [`serve::bring_up`] takes the tenure that sequence acquired to a `Live` owner endpoint. [`serve::serve`]
//! polls that owner until one exit ends the tenure and tears it down, and [`serve::wait`] holds a parked process,
//! which leaves when its role changed. [`recover::stand_by`] is the wait of a standby or unnamed host: it publishes
//! the wait's status to the host agent, enrolls an attached host's pair and runs the takeover a nomination starts.
//! [`lane`] runs a serving tenure's store requests on a thread apart from the owner's, and [`duties`] submits them
//! from each serving turn.
//! [`link`] is the owner-agent codec, the status cell an owner publishes to and the inbox that queues inbound
//! `Nominate`, `Peer`, and `Request` messages for the owner.
//! [`agent`] is the host agent's turn: it sends heartbeats and indirect probes, answers other hosts' probes, seals
//! the host report once per period and nominates the local standby process.
//!
//! Invariants:
//!
//! - HOST-GATE: every entry point that drives a device or a store write for an owner process takes a [`HostGate`],
//!   and only test builds construct one, so no production path reaches the composition.
//! - ROLE-LICENSES-NOTHING (`NoEpochReuse`, `RecordsBeforeDevice`): the role read issues at most two store reads and
//!   no store write, and touches no device; its shard read may persist a raised watermark to the client's local log.
//!   Each sequence rereads its own records at its step 1 and mints its session only from its own acknowledged write,
//!   so a role that the records stopped supporting refuses at that step.
//! - READ-ORDER: the role read takes the volume record before the shard record, as every check of
//!   `failover::poll` does.
//! - ONE-EXIT: an incarnation's recovery attempt ends through exactly one [`Exit`]. The exits that park keep the
//!   process running with no device while it rereads its role, and the process leaves the park through
//!   `Rerun::RoleChanged` with no second attempt; the others end the process, and its next incarnation derives its
//!   role again.

pub mod agent;
pub mod duties;
pub mod exit;
pub mod fencer;
pub mod gate;
pub mod inputs;
pub mod lane;
pub mod link;
pub mod recover;
pub mod serve;

pub use agent::Agent;
pub use duties::Duties;
pub use exit::{Exit, Refusal, Rerun};
pub use gate::HostGate;
pub use inputs::Inputs;
pub use lane::{Done, Job, Lane};
pub use link::{Inbound, Link, Status};
pub use recover::{
    Ended, Recovery, Role, Signals, Sources, Tenure, recover, role, stand_by, survey,
};
pub use serve::{
    Attachment, BringUp, Custody, Endpoint, Served, Teardown, Unbrought, bring_up, serve, teardown,
    wait,
};

#[cfg(test)]
mod agent_composed_tests;
#[cfg(test)]
mod exit_tests;
#[cfg(test)]
mod fencer_tests;
#[cfg(test)]
mod inputs_tests;
#[cfg(test)]
mod recover_tests;
#[cfg(test)]
mod standby_tests;
#[cfg(test)]
mod wait_tests;
