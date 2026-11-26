//! The owner-thread device volume: one command table, fixed arrays of read operations and write sets, and a bounded tick.
//!
//! Invariants owned by this module:
//!
//! - ONE-WRITER: a storage attaches one [`Volume`] over its life; attach claims the storage's set-once bit only after every check passed, so a refused attach builds nothing and leaves the bit, the budget and the driver as they were.
//!   The volume is neither `Send` nor `Sync` and keeps its borrows of the storage and the arena to the end of its scope.
//! - Tick bounds: one [`Volume::poll_storage`] call applies at most `terminal_burst` terminals and only while its output has two spare slots, folds at most `validate_bytes` bytes into checksums, submits at most `submit_burst` commands, never grows its output and allocates nothing outside the warm bootstrap, whose ticks start the attempt's recovery helpers and adopt at most `adopt` helper terminals, whose marks and allocator hold do whole-load work in one tick, whose install ticks take at most the `warm` module's run per lane and whose publication ticks that run per destination, and whose parallel stages start and join at most one scoped worker per lane within the tick; and outside a suffix log's delta stage, for an open log and for a closed one whose sealed blocks still drain, which encodes and checksums one sealed block into the buffer of each write attempt, whose sealed and written blocks grow the log's two block queues and its spare-payload list, each when its occupancy passes the capacity it holds, within the queue bound, and whose persisted write returns the block's payload to the log, where it serves a later block while the log is open.
//!   Attach allocates and charges every array, the ready set, the token map and the terminal scratch vector; the scratch vector holds `terminal_burst` terminals, which also bounds the terminals one `close` takes.
//! - Exposure: a read hands off payload bytes only as a [`ValidatedChunk`] covering chunks that verified, after its header verified, with the verified checksum of each window it spans kept in the volume's row for its buffer ([`Volume::chunk_crcs`]) while the chunk lives; header bytes, a buffer with unverified chunks and the buffer of a failed, short or quiesced command are never exposed.
//!   Each admitted read ends with exactly one `Done` once ticks apply its terminal, reach its deadline or follow a proven stop, and no `Chunk` follows it; releasing the volume drops outcomes no tick delivered.
//!   Every `Chunk` and the `Done` of a read whose header verified carry its [`VerifiedReadInfo`], so an empty payload's success names its record with no `Chunk`, and a read that failed before its header verified carries none.
//! - Progression: [`Volume::read`] submits a read's first command, or keeps it waiting under a kept grant when reads hold all `read_commands` table slots or the table or device queue is full, and the command starts at the record's first byte and reads as many whole windows as one command carries, at least every window of the largest admissible local header plus one chunk, ending early at the read's end, the locator's record end rounded up to the device block; each later whole-window command waits for one [`Volume::grant_read`], which submits it when the read is waiting, keeps the grant for a tick with room when the pool, the read share, the table or the device queue refuses that submit as full, and otherwise, on a volume that reads ahead, submits the next command ahead when its current command is outstanding or verifying, it holds fewer than `read_ahead` commands ahead and more of the record remains, before or after the header verified, with the same retry when that submit finds no room, or keeps the grant for the tick that verifies the outstanding command; a kept grant admits one command, and an ended read submits nothing more.
//!   Commands ahead submitted before the header verified each start at the previous command's end window and take their chunk ranges, in order, from the verified header; when the header fails, each command ahead's buffer returns uninspected after its terminal.
//!   A command ahead's bytes wait unverified until the current command hands off its chunks, then become the current command, so chunks still reach the caller in payload order. A cancel or a deadline quarantines every command the read holds, and the record frees after every terminal.
//!   A read waiting for a grant holds no buffer and no table slot; a tick ends it at its deadline, the ticks after `close` end it `Quiesced`, and a lost volume ends it `Lost`.
//! - Drain: `read_drained` is true for a handle once its record freed, which happens only after its `Done` was delivered and its last command reached its terminal, or, for a submit whose driver call unwound, at the first tick after the proven stop; a delivered `Done` alone proves no drain.
//! - Custody: a submitted buffer, its token, and the read operation or write set it serves stay held until the command's terminal event or a proven stop; cancel detaches the command in the table, and the next tick with output room delivers `Done { Cancelled }` while the record waits for that terminal; a tick at or past a read's deadline does the same with `Done { TimedOut }`, and cancels the command only while the table holds it pending with admission open or lost; an unmapped terminal is counted stale and changes nothing.
//!   Cancelled commands stay quarantined against the table's depth until their terminals; a table they fill with pending commands refuses submits `TableFull` with the abandoned count, and nothing waits.
//! - Loss: a table admission of `Lost` or unwinding from a tick or `close` permanently loses the volume. A lost volume returns `Lost` from `read` and `receive`, and [`WritableFill::publish`](super::WritableFill::publish) refuses a fill's publication on it with `Lost`, whether or not the fill's writes ended. Operations end `Lost` at the next tick with output room when nothing is outstanding or bytes are under verification, including while a command ahead is outstanding. Operations awaiting their current command end `Lost` at that command's terminal. A read whose driver call unwound during submission stays held until a proven stop.
//!   A write whose submit's driver call unwound stays counted in its set, so the set keeps its right until the first tick or `release` after the proven stop fails the set and releases the right.
//! - Early drop: dropping the volume before a proven quiesce frees nothing, so every buffer a command holds stays owned, the arena refuses release, and each operation's right stays counted, which keeps finalization blocked; a new storage, whose attach writes a new, higher tenure session, is the recovery.
//!   Reads hold at most `read_commands` table slots together, one token each, and metadata commands at most `metadata_commands`, so `depth - read_commands - metadata_commands - report_commands` slots stay for writes, which also hold each metadata slot no metadata command claims (WRITE-ROOM, the `write` module); `read_ops` bounds the read records, which may outnumber the depth.
//! - ResponseInIncarnation and NoStaleEpochWriteLands: serving admission checks the current token and Report window before reads, fills, metadata submissions and replies. Serving outside the window preserves writer state and command custody; Withdrawn refuses every admission and medium command and preserves command custody; after a deposing status it submits only the Reports of STATUS-REJUDGE, and after a lapsed deferral's withdrawal (`Cause::Unverified`) only its periodic Reports, while the flip stays open.
//! - Bootstrap: authority-admitted ticks after attach pass the attach gate (the `fence` module) on a restart's fencing-boundary value or, under a serving machine that holds a token, through its Register, Acquire and Report, whose pass admits the driver's medium commands, then probe both root slots and RESET both slots before any payload write, as the `metadata` module states, or install a guarded slot load and commit allocation readiness with no root write (the `warm` module); fills refuse `Bootstrapping` until the readiness reaches `Live`, at `begin_replay` over no restored binding or at `complete_replay` after a warm bootstrap, and every record a fill writes carries the tenure's session.
//! - A write set counts units complete only at a `Written` terminal; any other terminal fails the set, and a failed set never becomes ready.
//! - In-flight rights: a write set holds one right in its slot's count while any of its commands is outstanding, installed from a zero count before the submit that finds none outstanding and released at the terminal that leaves none; a read operation made by [`Volume::read`] or [`Volume::read_key`] holds the right its lease or its lookup reserved from its admission until its record frees, after its last terminal. A refused first read submit that ends the read releases the read's right, and a refused write submit releases the right it installed, before returning.
//! - Storage callers: [`WritableFill::receive`](super::WritableFill::receive) drives a fill's write set and [`WritableFill::publish`](super::WritableFill::publish) checks that the volume is not lost, then its serving authority, then the set's readiness; a hit's [`ExtentLease`](super::ExtentLease) is consumed by [`Volume::read`].
//! - `close` closes admission and advances quiesce; `release` consumes the volume only once the quiesce is proven, and a proven stop ends device access to host memory only: writes outstanding at the stop have unknown outcomes, and their sets fail.

pub(crate) mod activation;
#[cfg(test)]
mod activation_tests;
#[cfg(test)]
mod ahead_tests;
mod attach;
#[cfg(test)]
mod attach_gate_tests;
mod authority;
#[cfg(test)]
mod authority_tests;
#[cfg(test)]
mod reclaim_tests;
#[cfg(test)]
pub(crate) use authority::lapse_plant;
#[cfg(test)]
pub(crate) use authority::reclaim_plant;
pub use authority::{
    AuthorityRefusal, AuthorityReport, BootClock, HoldState, PolledReport, RegistrantJudgment,
    ServingAuthority, ServingClock,
};
#[cfg(test)]
mod bootstrap_tests;
pub(crate) mod checkpoint;
mod clock;
#[cfg(test)]
mod clock_tests;
mod config;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod coverage_tests;
mod cpus;
#[cfg(test)]
mod cursor_tests;
mod fence;
#[cfg(test)]
pub(crate) mod gate_fixture;
#[cfg(test)]
mod generation_tests;
#[cfg(test)]
mod grant_tests;
mod helpers;
#[cfg(all(test, loom))]
mod helpers_model;
#[cfg(test)]
mod helpers_tests;
#[cfg(test)]
mod journal_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod lost_waiting_read_tests;
mod metadata;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
pub(crate) use metadata::{PLANT, Plant};
mod placement;
pub use placement::PlacementRefusal;
pub(crate) use placement::place;
#[cfg(test)]
mod placement_tests;
mod read;
#[cfg(test)]
mod read_ahead_tests;
#[cfg(test)]
mod read_end_tests;
#[cfg(test)]
mod read_replay_tests;
#[cfg(test)]
mod read_share_tests;
#[cfg(test)]
mod read_tests;
mod readiness;
#[cfg(test)]
mod readiness_tests;
mod ready;
#[cfg(kani)]
mod ready_kani;
mod report;
#[cfg(test)]
mod report_tests;
#[cfg(test)]
mod reuse_tests;
#[cfg(test)]
mod suffix_rewrite_tests;
mod tick;
#[cfg(test)]
mod tick_tests;
#[cfg(test)]
mod volume_tests;
mod warm;
pub use warm::WarmSource;
#[cfg(test)]
pub(crate) use warm::cycle_tests as warm_cycle;
#[cfg(test)]
pub(crate) use warm::sim_tests as warm_sim;
#[cfg(all(test, loom))]
mod warm_model;
#[cfg(test)]
mod withheld_report_gate_tests;
mod write;
#[cfg(test)]
pub(crate) mod write_guard;
#[cfg(test)]
mod write_guard_tests;
#[cfg(test)]
mod write_tests;

#[cfg(test)]
pub(crate) use attach::Bound;
pub(crate) use attach::ReadShape;
pub use attach::{TickReport, Volume, VolumeReport};
pub use config::{
    AttachError, GeometryRefusal, TickConfig, VolumeConfig, VolumeGeometry, VolumeWatermarks,
};
#[cfg(test)]
pub(crate) use config::{
    TEST_CLOCK, TEST_FEED, TEST_METADATA_UNITS, test_recovery, test_volume, test_volume_with,
};
pub use cpus::{CpuSet, MAX_CPUS};
pub use fence::{Fenced, GateRefusal, GateStep};
#[cfg(test)]
pub(crate) use helpers::ENCODE_PANIC;
pub use helpers::RecoveryLimits;
pub(crate) use helpers::contain;
#[cfg(test)]
pub(crate) use helpers::{INLINE as INLINE_RECOVERY, PARK as PARK_RECOVERY};
#[cfg(all(test, not(loom)))]
pub(crate) use helpers_tests::helpers_run_on_one_thread;
#[cfg(test)]
pub(crate) use helpers_tests::{Bomb, Dropped};
#[cfg(test)]
pub(crate) use read::RawRead;
pub(crate) use read::ReadSpan;
pub use read::{
    ControlRefusal, Grant, KeyReadError, MAX_READ_AHEAD, ReadEvent, ReadOp, ReadRefusal,
    ReadRefused, ReadStatus, ValidatedChunk, VerifiedReadInfo,
};
pub(crate) use read::{JoinedRefusal, KeyRead};
pub use report::{
    PhaseReport, RECOVERY_PHASES, RECOVERY_TRANSITIONS, RecoveryPhase, RecoveryReport, Transition,
};
pub use write::WriteProgress;
pub(crate) use write::WriteSet;
