//! Kestrike's AWS client: one SigV4-signed blocking HTTPS request
//! per `Client::send`, under one deadline, with instance-role credentials
//! read through IMDSv2. The crate builds on 64-bit Linux, where
//! `kestrike::bind` provides the metadata client.
//!
//! The [`ec2`] module holds the reconciler's EC2 reads over that client
//! and, in `ec2::VolumeActions`, its create, attach and detach requests.

#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

mod client;
mod clock;
mod config;
mod credentials;
mod dial;
mod dynamo;
#[cfg(test)]
mod fake_table;
#[cfg(test)]
mod loopback;
mod sign;
#[cfg(test)]
#[path = "store_record_tests.rs"]
mod store_record;
mod wire;

pub mod ec2;

pub use client::{Call, Client, Fault, Stage};
pub use clock::{Clock, SystemClock};
pub use config::{Config, DYNAMODB, EC2, MAX_DEADLINE, Service};
pub use credentials::{REFRESH_MARGIN, REFRESH_WAIT, Role};
pub use dynamo::{OpenError, Table};
pub use wire::{Https, IDLE_AGE, Lost, LostAt, Reply, Request, Wire};
