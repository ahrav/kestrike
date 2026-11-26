//! Attachment admission checks, in first-failure order, before any device effect, and the local-record rule they apply.
//!
//! LOCAL-RECORD-ONCE: the fresh path produces a record only at `E = 0`; the caller persists it before the `E` compare-and-swap and registers the pair after that succeeds. A valid record matching the binding and key incarnation preserves its full key and host ID, including across epoch differences and reruns with stale `E = 0`. An absent, invalid, or differently bound record yields a new record. An unreadable existing file or a matching binding with another key incarnation causes refusal before writing. At `E > 0`, the fresh path returns `AdmissionError::AttemptConsumed`. Connects read the existing record through [`validate_record`], requiring a valid record with the matching binding and key incarnation.
//!
//! The fresh path persists the record before it enrolls the record's pair in the volume record, and enrolls the pair before Register. The standby's persist (`bind::OwnerLock::persist_standby`) applies the same keep-or-draw rule through [`kept_or_drawn`] at any `E`, after its own retained-refusal check, and writes the record before the standby's enrollment; it writes only a record whose full key is the requested key, draws only under the assignment's attach key, and otherwise refuses `Key` with no write. Fresh and connect keep the incarnation-only rule.
//!
//! ONE-KEY-PER-ATTACHMENT: [`owned`]'s key check accepts matching incarnations across epoch differences.

use super::assignment::AuthenticatedAssignment;
use super::identity::Key;
use super::record::{Binding, LocalRecord, RecordError};

/// A typed first failure of production attachment admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    Instance,
    /// A connect found no local record.
    Record,
    Volume,
    DeleteOnTermination,
    Az,
    /// The local record's binding differs from the assignment's instance, volume or attachment, or the mappings file names another instance or boot.
    Binding,
    /// The local record bound to this attachment holds another key incarnation; for a standby's persist, also a
    /// requested key whose incarnation is not the signed assignment's, or a local record of this attachment whose key
    /// has the requested incarnation under another epoch.
    Key,
    Retained,
    /// A fresh-path record write found `E > 0`: an attempt was consumed, so the record stays as written.
    AttemptConsumed,
    Entropy,
    StateDirectory,
    HostKey,
    Assignment(super::assignment::AssignmentError),
    RecordCodec(RecordError),
    DurableWrite,
}

/// A fresh-path failure: `Admission` for a refusal or a failed record write before the compare-and-swap ran, `Cas` for the compare-and-swap's own error after the record was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshError<C> {
    Admission(AdmissionError),
    Cas(C),
}

impl<C> From<AdmissionError> for FreshError<C> {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}

/// Checks instance, volume, deletion observation and AZ, and returns the binding the assignment names.
///
/// # Errors
///
/// Refuses in instance, volume, deletion observation and AZ order.
pub fn admit(
    assignment: &AuthenticatedAssignment,
    instance: &str,
    az: impl FnOnce() -> Result<String, AdmissionError>,
    volume: &str,
) -> Result<Binding, AdmissionError> {
    let a = assignment.fields();
    if a.instance != instance {
        return Err(AdmissionError::Instance);
    }
    if a.volume != volume {
        return Err(AdmissionError::Volume);
    }
    if a.delete_on_termination != Some(false) {
        return Err(AdmissionError::DeleteOnTermination);
    }
    if a.az != az()? {
        return Err(AdmissionError::Az);
    }
    Ok(Binding {
        instance: a.instance.clone(),
        volume: a.volume.clone(),
        attachment: a.attachment.clone(),
    })
}

/// Matching the binding and incarnation preserves the full stored key across epoch differences.
///
/// # Errors
///
/// `Key` for a record of the same binding that holds another incarnation, since an attachment keeps one key for its life.
fn owned(record: &LocalRecord, binding: &Binding, key: Key) -> Result<bool, AdmissionError> {
    if record.binding() != binding {
        return Ok(false);
    }
    if record.pair().key.incarnation() != key.incarnation() {
        return Err(AdmissionError::Key);
    }
    Ok(true)
}

/// The fresh path's record at `attempt`, persisted before the `E` CAS. At `attempt = 0`, `existing` is read;
/// a valid record matching the binding and incarnation preserves its full key and host ID. An absent, invalid
/// or differently bound record yields a new record with `key` and a host ID from `draw`.
///
/// # Errors
///
/// `AttemptConsumed` when `attempt > 0`, before `existing` or `draw` runs; `existing`'s error for a record file that exists and cannot be read; `Key` for a record bound to `binding` that holds another key incarnation; `Entropy` when `draw` yields no host ID.
pub fn fresh(
    binding: Binding,
    key: Key,
    attempt: u32,
    existing: impl FnOnce() -> Result<Option<Result<LocalRecord, RecordError>>, AdmissionError>,
    draw: impl FnMut() -> Option<[u8; 16]>,
) -> Result<LocalRecord, AdmissionError> {
    if attempt > 0 {
        return Err(AdmissionError::AttemptConsumed);
    }
    kept_or_drawn(binding, key, existing()?, draw)
}

/// The record a host persists for `binding` under `key`: `existing` with its full stored key and host ID when it is
/// valid, bound to `binding` and holding `key`'s incarnation, and otherwise, for an absent, invalid or differently
/// bound record, a new record with `key` and a host ID from `draw`. It selects the record and writes nothing: it
/// reads no `E` and no retained refusal, which its callers check first. [`fresh`] refuses `attempt > 0` before it,
/// and the standby's persist calls it at any `E` after its retained-refusal check, then refuses `Key` unless the
/// selected record's full key is the requested key; each caller then writes the record.
///
/// # Errors
///
/// `Key` for a record bound to `binding` that holds another key incarnation; `Entropy` when `draw` yields no host
/// ID.
pub fn kept_or_drawn(
    binding: Binding,
    key: Key,
    existing: Option<Result<LocalRecord, RecordError>>,
    draw: impl FnMut() -> Option<[u8; 16]>,
) -> Result<LocalRecord, AdmissionError> {
    if let Some(Ok(record)) = existing
        && owned(&record, &binding, key)?
    {
        return Ok(record);
    }
    LocalRecord::fresh(binding, key, draw).ok_or(AdmissionError::Entropy)
}

/// The record a connect uses, after a fresh first acquisition or at a restart: `existing` when it is present, valid,
/// bound to `binding` and holding `key`'s incarnation, preserving its full stored key and host ID.
///
/// # Errors
///
/// `Record` for an absent record, `RecordCodec` for an invalid one, `Binding` for a record bound to another
/// instance, volume or attachment, and `Key` for a record matching the binding that holds another key incarnation.
pub fn validate_record(
    binding: &Binding,
    key: Key,
    existing: Option<Result<LocalRecord, RecordError>>,
) -> Result<LocalRecord, AdmissionError> {
    let record = existing
        .ok_or(AdmissionError::Record)?
        .map_err(AdmissionError::RecordCodec)?;
    if !owned(&record, binding, key)? {
        return Err(AdmissionError::Binding);
    }
    Ok(record)
}
