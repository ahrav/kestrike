//! The reconciler status: one authenticated, bounded record per reconciler pass that carries, for each availability
//! zone the reconciler runs, the serving class of every shard and the standby, census, attach-slot, receipt,
//! volume-health, host, budget and store counts, with bounded exception rows. It is telemetry for operators and an
//! external alarm evaluator, and it has no store key.
//!
//! A 48-byte header (`RSTS`, [`SCHEMA`], writer host, boot nonce, sequence, seal time, zone count, a zero byte)
//! precedes one [`ZonePart`] per zone in ascending zone order and a 32-byte tag, through the envelope the host report
//! shares ([`super::Writer`]). Each part is [`PART_LEN`] bytes and 14 bytes per exception row. The operator contract,
//! `failover/report/status_contract.json`, pins the layout, the label tables, each field's unit and sealed fixtures.
//!
//! Invariants owned here:
//!
//! - STATUS-AUTHENTICATED: the tag is HMAC-SHA256 under the writer's [`StatusKey`] over the 16-byte domain label
//!   `ebs-recon-status` and the body. [`StatusKey::derive`] computes that key from the reconciler's key under a
//!   label of its own, so a verifier holds a key that authenticates statuses only, and a host report key verifies
//!   no status. [`StatusReader::accept`] reads only the magic, the schema, the byte length and the writer before
//!   the tag verifies in constant time, and reads the zone count after it.
//! - STATUS-BOUNDED: a status holds at most [`MAX_ZONES`] parts and each part at most [`MAX_ROWS`] exception rows,
//!   oldest first, with the count of the rows left out, so a status is at most [`MAX_LEN`] bytes, within 16 KiB, as
//!   a compile-time assertion checks.
//! - CLOSED-LABELS: every label byte selects from a closed table and the decoder refuses any other byte; each
//!   count array is indexed by a closed table (`part`), and the conversions from the steps' types match
//!   exhaustively (`events`). A shard is a field.
//! - WRITER-SEQUENCE: as for the host report, a writer's sequence rises by one per sealed status from 1, and a
//!   [`StatusReader`] drops a status at or below the highest sequence it accepted from that writer.
//! - REPORTS-CONFER-NO-AUTHORITY: this module holds no store client, device handle or reconciler. The builder reads
//!   the survey's rows, the records and the reports through shared borrows, and building or sealing a status makes
//!   no store write, releases no hold and changes no ownership. No production code reads a status, and the store
//!   client stores no status:
//!
//! ```compile_fail,E0277
//! # use kestrike::failover::report::status::ReconcilerStatus;
//! # use kestrike::storage::store::{Client, Key, Store, WatermarkLog};
//! fn store<S: Store, L: WatermarkLog>(client: &mut Client<S, L>, key: Key, status: ReconcilerStatus) {
//!     let _ = client.create(key, status);
//! }
//! ```
//!
//! [`Events`] counts start at zero on loop startup. Store outcome counts measure changes from the store client's
//! tally at loop construction.

use crate::failover::report::WriterId;

mod build;
mod codec;
mod events;
mod part;

pub use build::{Builder, Clock, Memory};
pub use codec::{StatusKey, StatusReader, StatusWriter};
pub use part::{
    ATTACHES, AttachOutcome, Attaches, BLOCKERS, Budgets, CLASSES, CREATES, Class, Create,
    DECISIONS, Decided, ENROLLMENTS, Enrollment, Events, ExceptionRow, Flags, Hosts, RECEIPTS,
    RECLAIMS, REFUSED, RESERVATIONS, ReceiptCount, Reclaim, Refused, Reservation, STANDBYS,
    STEP_ERRORS, STORE_ALARMS, Standby, StepError, StoreAlarm, StoreState, ZonePart, closed_at,
    health_at, need_at, positions, verdict_at,
};

/// The body version this module encodes and the only one its reader accepts.
pub const SCHEMA: u16 = 1;
/// The most zone parts one status holds.
pub const MAX_ZONES: usize = 16;
/// The most exception rows one zone part holds.
pub const MAX_ROWS: usize = 32;
/// One zone part without its rows.
pub const PART_LEN: usize = codec::PART_LEN;
/// One exception row: the shard (4), the class and standby labels and the age (8).
pub const ROW_LEN: usize = 4 + 1 + 1 + 8;
/// The length of a status of [`MAX_ZONES`] parts of [`MAX_ROWS`] rows each.
pub const MAX_LEN: usize =
    super::HEADER_LEN + MAX_ZONES * (PART_LEN + MAX_ROWS * ROW_LEN) + super::TAG_LEN;

const _: () =
    assert!(MAX_LEN <= 16 * 1024 && MAX_ZONES <= u8::MAX as usize && MAX_ROWS <= u8::MAX as usize);

/// One decoded status: its writer metadata and one part per zone, in ascending zone order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilerStatus {
    pub writer: WriterId,
    pub sequence: u64,
    /// The writer's wall-clock stamp in microseconds since the Unix epoch at the seal, nondecreasing within a boot.
    pub sealed_at_us: u64,
    pub zones: Vec<ZonePart>,
}

#[cfg(test)]
#[path = "../status_tests.rs"]
pub(crate) mod tests;
