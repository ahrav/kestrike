//! Verus proofs of kestrike cores, compiled from the production files they verify.
//!
//! Each core module is the production source file, included by path, so the verifier and an ordinary build read the same bytes.
//! `model` states what the cores compute as a unit-by-unit reading of the state they summarize; `proof` holds the lemmas the cores' contracts call.

#[path = "../../../crates/kestrike/src/storage/extent/summary.rs"]
pub mod summary;

#[path = "../../../crates/kestrike/src/storage/extent/plan.rs"]
pub mod plan;

#[path = "../../../crates/kestrike/src/storage/device/custody.rs"]
pub mod custody;

#[path = "../../../crates/kestrike/src/storage/device/spdk/certify.rs"]
pub mod certify;

#[path = "../../../crates/kestrike/src/storage/geometry.rs"]
pub mod geometry;

#[path = "../../../crates/kestrike/src/storage/block_order.rs"]
pub mod block_order;

#[path = "../../../crates/kestrike/src/storage/record/arithmetic.rs"]
pub mod arithmetic;

#[path = "../../../crates/kestrike/src/storage/record/predicate.rs"]
pub mod predicate;

#[path = "../../../crates/kestrike/src/storage/extent/partition.rs"]
pub mod partition;

#[path = "../../../crates/kestrike/src/storage/recovery/layout.rs"]
pub mod layout;

#[path = "../../../crates/kestrike/src/storage/recovery/durable.rs"]
pub mod durable;

#[path = "../../../crates/kestrike/src/storage/portable/expiry.rs"]
pub mod expiry;

#[path = "../../../crates/kestrike/src/storage/coverage/step.rs"]
pub mod step;

pub mod model;
pub mod owners;
pub mod proof;

#[path = "../../../crates/kestrike/src/failover/route_merge.rs"]
pub mod route_merge;

#[path = "../../../crates/kestrike/src/failover/window.rs"]
pub mod window;
