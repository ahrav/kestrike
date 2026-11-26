//! Persistent authority preparation under the attachment's owner lock.

use super::{Host, Imds, Mappings, Metadata, OwnerLock};
use crate::failover::admission::{self, AdmissionError, FreshError};
use crate::failover::assignment::{self, AuthenticatedAssignment};
use crate::failover::identity::{Incarnation, Key, is_az};
use crate::failover::record::{Binding, LocalRecord, RECORD_BYTES, RecordError};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Durable assignment/record agreement used by the production driver.
#[derive(Debug)]
pub(crate) struct AttachAuthority {
    pub(crate) record: LocalRecord,
}
impl AttachAuthority {
    pub(crate) fn pair(&self) -> crate::failover::evidence::Pair {
        self.record.pair()
    }
}

pub(crate) fn private_read(path: &Path, bound: usize, owner: u32) -> std::io::Result<Vec<u8>> {
    Mappings::read_bytes(path, bound as u64, |meta| {
        meta.mode() & 0o777 == 0o600 && meta.uid() == owner
    })
}

/// One host-ID draw from `fill`: the filled bytes, all-zero ones included, so [`LocalRecord::fresh`] owns the redraw of a zero host ID; `None` when `fill` fails.
pub(super) fn host_id_draw(
    fill: impl FnOnce(&mut [u8; 16]) -> Result<(), crate::entropy::EntropyError>,
) -> Option<[u8; 16]> {
    let mut bytes = [0; 16];
    fill(&mut bytes).ok().map(|()| bytes)
}

pub(crate) const REFUSAL_PREFIX: &str = "authority-refused-";

/// The zero separators preserve field boundaries in the hash input.
pub(super) fn refusal_name(binding: &Binding, incarnation: Incarnation) -> String {
    let mut digest = Sha256::new();
    digest.update(b"fresh-refusal-v1");
    for value in [&binding.instance, &binding.volume, &binding.attachment] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    digest.update(incarnation.get().to_le_bytes());
    format!("{REFUSAL_PREFIX}{}", super::wc::hex(digest.finalize()))
}

impl OwnerLock {
    /// Writes `record` as the state directory's local record; a test seeds a connect's record through it.
    #[cfg(test)]
    pub(crate) fn persist_local(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        self.check_authority_directory()?;
        self.write_local(record)
    }
    /// The one writer of the local record, which production code reaches through the fresh path and the unnamed
    /// host's enrollment.
    ///
    /// The caller ran `check_authority_directory` in this preparation and holds the owner lock. The crate writes `authority` and `mappings` only under that lock, and the directory check found every ancestor owned by root or the directory's owner with no group or other write bit, so only root or that owner can replace the directory, and this write reuses the check.
    fn write_local(&self, record: &LocalRecord) -> Result<(), AdmissionError> {
        self.write_record_file("authority", record)
    }

    fn write_record_file(&self, name: &str, record: &LocalRecord) -> Result<(), AdmissionError> {
        let bytes = record.encode().map_err(AdmissionError::RecordCodec)?;
        Mappings::write_bytes(&self.state_dir().join(name), &bytes)
            .map_err(|_| AdmissionError::DurableWrite)
    }
    /// The local record: `None` for an absent file, otherwise the decoded sector of a private regular file of `owner` of at most one sector.
    ///
    /// # Errors
    ///
    /// `RecordCodec(Length)` for a file that exists and whose metadata cannot be read, that fails those checks, or that cannot be read.
    fn read_local(
        &self,
        owner: u32,
    ) -> Result<Option<Result<LocalRecord, RecordError>>, AdmissionError> {
        self.read_record_file(owner, "authority")
    }

    fn read_record_file(
        &self,
        owner: u32,
        name: &str,
    ) -> Result<Option<Result<LocalRecord, RecordError>>, AdmissionError> {
        let path = self.state_dir().join(name);
        let unreadable = AdmissionError::RecordCodec(RecordError::Length);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unreadable),
            Ok(_) => {}
        }
        let bytes = private_read(&path, RECORD_BYTES, owner).map_err(|_| unreadable)?;
        Ok(Some(LocalRecord::decode(&bytes)))
    }

    fn retained_refusal(
        &self,
        owner: u32,
        binding: &Binding,
        incarnation: Incarnation,
    ) -> Result<bool, AdmissionError> {
        let Some(record) = self.read_record_file(owner, &refusal_name(binding, incarnation))?
        else {
            return Ok(false);
        };
        let record = record.map_err(AdmissionError::RecordCodec)?;
        if record.binding() != binding || record.pair().key.incarnation() != incarnation {
            return Err(AdmissionError::Binding);
        }
        Ok(true)
    }

    /// Checks that the state directory is a 0700 directory of this process's
    /// user that passes `private_canonical`, with a canonical form outside
    /// `/run` and `/var/run`, and returns that user's ID, which `host.key`,
    /// `assignment` and `authority` must carry.
    pub(crate) fn check_authority_directory(&self) -> Result<u32, AdmissionError> {
        let owner = fs::metadata("/proc/self")
            .map_err(|_| AdmissionError::StateDirectory)?
            .uid();
        let meta =
            fs::symlink_metadata(self.state_dir()).map_err(|_| AdmissionError::StateDirectory)?;
        if meta.uid() != owner || !meta.is_dir() || meta.mode() & 0o777 != 0o700 {
            return Err(AdmissionError::StateDirectory);
        }
        let path = super::binder::private_canonical(self.state_dir(), owner)
            .map_err(|_| AdmissionError::StateDirectory)?;
        if path.starts_with("/run") || path.starts_with("/var/run") {
            return Err(AdmissionError::StateDirectory);
        }
        Ok(owner)
    }
    /// The state directory's owner and its verified assignment.
    fn assignment(&self) -> Result<(u32, AuthenticatedAssignment), AdmissionError> {
        let owner = self.check_authority_directory()?;
        let key: [u8; 32] = private_read(&self.state_dir().join("host.key"), 32, owner)
            .map_err(|_| AdmissionError::HostKey)?
            .try_into()
            .map_err(|_| AdmissionError::HostKey)?;
        let bytes = private_read(
            &self.state_dir().join("assignment"),
            assignment::ASSIGNMENT_BYTES,
            owner,
        )
        .map_err(|_| AdmissionError::Assignment(assignment::AssignmentError::Length))?;
        let assignment = assignment::verify(&bytes, &key).map_err(AdmissionError::Assignment)?;
        Ok((owner, assignment))
    }
    /// Prepares the authority a connect uses, confirming the instance through `metadata`: the admission checks, then the existing local record, which must be present, valid and bound to the assignment's instance, volume and attachment. It writes nothing.
    ///
    /// A present record does not by itself authorize a connect: after a fresh first acquisition, the caller connects only after its `E` compare-and-swap succeeded with an acknowledgment, and a failed or unacknowledged compare-and-swap is never followed by a connect.
    ///
    /// # Errors
    ///
    /// `StateDirectory`, `HostKey` and `Assignment` for the state directory, host key and assignment, and `Instance` for an instance `metadata` does not confirm; the admission checks' errors; `Binding` for a mappings file that names another instance or boot; `Record` when no `authority` file exists; `RecordCodec(Length)` for an `authority` file that cannot be inspected or read or is not a private regular file of at most one sector, and `RecordCodec` for a sector that fails decoding; `Binding` for a record bound to another instance, volume or attachment; `Key` for a record that holds another key incarnation than the assignment; `Retained` for a refused attachment.
    pub(crate) fn prepare_authority(
        &self,
        host: &Host,
        metadata: &dyn Metadata,
    ) -> Result<AttachAuthority, AdmissionError> {
        let (owner, assignment) = self.assignment()?;
        self.prepare_checked(owner, host, metadata, assignment)
    }
    #[cfg(test)]
    pub(crate) fn prepare_verified(
        &self,
        host: &Host,
        metadata: &dyn Metadata,
        assignment: AuthenticatedAssignment,
    ) -> Result<AttachAuthority, AdmissionError> {
        let owner = self.check_authority_directory()?;
        self.prepare_checked(owner, host, metadata, assignment)
    }
    /// Runs the fresh path's local-record step at the shard record's attempt counter `attempt`.
    ///
    /// The admission checks run first. At `attempt = 0` the step then durably writes the local record, and only after that write calls `cas`, the caller's `E: 0 -> 1` compare-and-swap. Once a valid record of the same binding and incarnation has landed, the step writes that record again with its full stored key and host ID, so a rerun at `E = 0`, one handed a stale `E = 0` included, keeps the host ID an earlier run wrote. An absent record, a sector that fails decoding and a record bound elsewhere get a newly drawn host ID. A record file that exists and cannot be read, and a record of the same binding with another key incarnation, refuse before any write. A failed `cas` leaves the record written. The step returns no record: the connect that follows reads it through `prepare_authority`.
    ///
    /// # Errors
    ///
    /// `Admission` with `StateDirectory`, `HostKey`, `Assignment` or `Instance` for the state directory, host key, assignment and metadata service; the admission checks' errors; `Retained` for a refused attachment, before any write; `AttemptConsumed` when `attempt > 0`, before the record read and any write; `RecordCodec(Length)` for a record file that exists and cannot be read; `Key`; `Entropy`; `RecordCodec`; or `DurableWrite`. `Cas` with `cas`'s error after the record is written.
    pub fn prepare_fresh<C>(
        &mut self,
        host: &Host,
        attempt: u32,
        key: Key,
        cas: impl FnOnce() -> Result<(), C>,
    ) -> Result<(), FreshError<C>> {
        let (owner, assignment) = self.assignment()?;
        let metadata = Imds::connect(60).map_err(|_| AdmissionError::Instance)?;
        self.fresh_checked(owner, host, &metadata, &assignment, attempt, key, cas)
    }
    #[cfg(test)]
    pub(crate) fn prepare_fresh_verified<C>(
        &mut self,
        host: &Host,
        metadata: &dyn Metadata,
        assignment: &AuthenticatedAssignment,
        attempt: u32,
        key: Key,
        cas: impl FnOnce() -> Result<(), C>,
    ) -> Result<(), FreshError<C>> {
        let owner = self.check_authority_directory()?;
        self.fresh_checked(owner, host, metadata, assignment, attempt, key, cas)
    }
    /// `owner` comes from this preparation's directory check, as for `prepare_checked`.
    #[expect(clippy::too_many_arguments)]
    fn fresh_checked<C>(
        &mut self,
        owner: u32,
        host: &Host,
        metadata: &dyn Metadata,
        assignment: &AuthenticatedAssignment,
        attempt: u32,
        key: Key,
        cas: impl FnOnce() -> Result<(), C>,
    ) -> Result<(), FreshError<C>> {
        let binding = self.binding(host, metadata, assignment)?;
        let a = assignment.fields();
        if self.retained_refusal(owner, &binding, a.incarnation)? {
            return Err(AdmissionError::Retained.into());
        }
        let record = admission::fresh(
            binding,
            Key::attachment(a.incarnation),
            attempt,
            || self.read_local(owner),
            || host_id_draw(crate::entropy::os_entropy),
        )?;
        if record.pair().key != key {
            return Err(AdmissionError::Key.into());
        }
        self.write_local(&record)?;
        cas().map_err(FreshError::Cas)
    }
    /// The local record an attached standby enrolls its pair from, durable when this returns: the unnamed host's
    /// `persist` step, which `failover::reconcile::enroll_standby` calls before its enrollment write with `key`. For a
    /// new enrollment `key` is the key of the standby's live attach entry (KEY-PER-ATTACH), epoch 1 and the entry's
    /// number plus one as incarnation; for a replay it is the key of the pair the volume record already pins for that
    /// attach. The signed assignment carries an incarnation, and `key`'s incarnation must be it, so the record this
    /// writes is the one a later restart's admission validates. After the admission checks it keeps a valid record
    /// bound to the assignment's instance, volume and attachment whose full key is `key`, with its stored host ID,
    /// and for an absent record, a sector that fails decoding or a record bound elsewhere builds a record for that
    /// binding and `key` with a newly drawn host ID, when `key` is the assignment's attach key `Key::attachment` of
    /// its incarnation. A replay under a retained key of another epoch persists only the kept record that holds it. It writes either record through the local-record writer on every
    /// call, so a record that an earlier call renamed into place before its directory sync failed is returned only
    /// after a write whose directory sync succeeded, with the host ID that earlier call drew. The record it returns
    /// always carries `key`.
    ///
    /// # Errors
    ///
    /// `StateDirectory`, `HostKey`, `Assignment` and `Instance`, and the admission checks' errors; `Key` for a `key`
    /// whose incarnation is not the assignment's, `Retained` for a refused attachment, `Key` for a record of this
    /// binding with another key incarnation, `Key` for a record of this binding whose key has `key`'s incarnation
    /// under another epoch, and `Key` for a retained key of another epoch that no kept record of this binding holds,
    /// each before any write; `RecordCodec(Length)` for a record file that exists and cannot be
    /// read; `Entropy`; `RecordCodec`; or `DurableWrite`.
    pub fn persist_standby(
        &self,
        host: &Host,
        metadata: &dyn Metadata,
        key: Key,
    ) -> Result<LocalRecord, AdmissionError> {
        let (owner, assignment) = self.assignment()?;
        let binding = self.binding(host, metadata, &assignment)?;
        let a = assignment.fields();
        if key.incarnation() != a.incarnation {
            return Err(AdmissionError::Key);
        }
        if self.retained_refusal(owner, &binding, a.incarnation)? {
            return Err(AdmissionError::Retained);
        }
        let existing = self.read_local(owner)?;
        let kept = |record: &LocalRecord| record.binding() == &binding && record.pair().key == key;
        if key != Key::attachment(a.incarnation)
            && !matches!(&existing, Some(Ok(record)) if kept(record))
        {
            return Err(AdmissionError::Key);
        }
        let record = admission::kept_or_drawn(binding, key, existing, || {
            host_id_draw(crate::entropy::os_entropy)
        })?;
        if record.pair().key != key {
            return Err(AdmissionError::Key);
        }
        self.write_local(&record)?;
        Ok(record)
    }
    /// The binding the admission checks admit: the instance against the instance metadata, the mappings file's instance, boot and volume, the deletion observation and the AZ.
    fn binding(
        &self,
        host: &Host,
        metadata: &dyn Metadata,
        assignment: &AuthenticatedAssignment,
    ) -> Result<Binding, AdmissionError> {
        let (instance, boot) = host.instance_and_boot().ok_or(AdmissionError::Instance)?;
        if metadata
            .get("instance-id")
            .map_err(|_| AdmissionError::Instance)?
            .trim()
            != instance
            || assignment.fields().instance != instance
        {
            return Err(AdmissionError::Instance);
        }
        let mappings = self.mappings().map_err(|_| AdmissionError::Volume)?;
        mappings
            .check_current(&instance, &boot)
            .map_err(|_| AdmissionError::Binding)?;
        let volume = &mappings.nvme.as_ref().ok_or(AdmissionError::Volume)?.volume;
        let az = || {
            let az = metadata
                .get("placement/availability-zone")
                .map_err(|_| AdmissionError::Az)?;
            let az = az.trim();
            if !is_az(az) {
                return Err(AdmissionError::Az);
            }
            Ok(az.to_owned())
        };
        admission::admit(assignment, &instance, az, volume)
    }
    /// `owner` comes from this preparation's directory check, which found the
    /// directory owned by `owner` with mode 0700 and every ancestor of its path
    /// as given and of its canonical form owned by root or `owner`, each
    /// directory among them with no group or other write bit; the record read
    /// requires a private regular file of that user.
    fn prepare_checked(
        &self,
        owner: u32,
        host: &Host,
        metadata: &dyn Metadata,
        assignment: AuthenticatedAssignment,
    ) -> Result<AttachAuthority, AdmissionError> {
        let binding = self.binding(host, metadata, &assignment)?;
        let a = assignment.fields();
        let key = Key::attachment(a.incarnation);
        let record = admission::validate_record(&binding, key, self.read_local(owner)?)?;
        if self.retained_refusal(owner, &binding, a.incarnation)? {
            return Err(AdmissionError::Retained);
        }
        Ok(AttachAuthority { record })
    }
}

impl crate::failover::restart::LocalSource for OwnerLock {
    fn local(&self) -> Result<LocalRecord, crate::failover::restart::Local> {
        use crate::failover::restart::Local;
        let owner = self
            .check_authority_directory()
            .map_err(|_| Local::Unreadable)?;
        match self.read_local(owner) {
            Ok(Some(record)) => {
                let record = record.map_err(Local::Invalid)?;
                if self
                    .retained_refusal(owner, record.binding(), record.pair().key.incarnation())
                    .map_err(|_| Local::Unreadable)?
                {
                    return Err(Local::Retained);
                }
                Ok(record)
            }
            Ok(None) => Err(Local::Absent),
            Err(_) => Err(Local::Unreadable),
        }
    }
}

/// The owner lock spans the mapping check and local-record write. The records borrow the lock shared, so the fresh
/// path's driver, which borrows the same lock for its life, connects while the records stay in use.
pub struct FreshRecords<'a> {
    pub lock: &'a OwnerLock,
    pub host: &'a Host,
    pub metadata: &'a dyn Metadata,
    pub binding: Binding,
    /// If `record.pair().key` differs from the `key` argument, `persist` returns `AdmissionError::Key` before writing
    /// the record.
    pub key: Key,
}

impl crate::failover::restart::LocalSource for FreshRecords<'_> {
    fn local(&self) -> Result<LocalRecord, crate::failover::restart::Local> {
        let record = self.lock.local()?;
        if record.binding() != &self.binding
            || record.pair().key.incarnation() != self.key.incarnation()
        {
            return Err(crate::failover::restart::Local::Binding);
        }
        Ok(record)
    }
}

impl crate::failover::fresh::LocalRecords for FreshRecords<'_> {
    fn persist(
        &mut self,
        holder: &crate::failover::poll::Holder,
        attempt: u32,
        key: Key,
    ) -> Result<LocalRecord, AdmissionError> {
        let owner = self.lock.check_authority_directory()?;
        let (instance, boot) = self
            .host
            .instance_and_boot()
            .ok_or(AdmissionError::Instance)?;
        if instance != holder.instance.as_str()
            || self.binding.instance != instance
            || self.binding.volume != holder.volume.as_str()
        {
            return Err(AdmissionError::Binding);
        }
        if self
            .metadata
            .get("instance-id")
            .map_err(|_| AdmissionError::Instance)?
            .trim()
            != instance
        {
            return Err(AdmissionError::Instance);
        }
        let mappings = self.lock.mappings().map_err(|_| AdmissionError::Volume)?;
        mappings
            .check_current(&instance, &boot)
            .map_err(|_| AdmissionError::Binding)?;
        if mappings.nvme.as_ref().ok_or(AdmissionError::Volume)?.volume != self.binding.volume {
            return Err(AdmissionError::Volume);
        }
        if self
            .lock
            .retained_refusal(owner, &self.binding, self.key.incarnation())?
        {
            return Err(AdmissionError::Retained);
        }
        let record = admission::fresh(
            self.binding.clone(),
            self.key,
            attempt,
            || self.lock.read_local(owner),
            || host_id_draw(crate::entropy::os_entropy),
        )?;
        if record.pair().key != key {
            return Err(AdmissionError::Key);
        }
        self.lock.write_local(&record)?;
        Ok(record)
    }

    fn retain_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        if record.binding() != &self.binding
            || record.pair().key.incarnation() != self.key.incarnation()
        {
            return Err(AdmissionError::Binding);
        }
        let name = refusal_name(record.binding(), record.pair().key.incarnation());
        let retained = self.lock.check_authority_directory().and_then(|owner| {
            self.lock
                .retained_refusal(owner, record.binding(), record.pair().key.incarnation())?;
            self.lock.write_record_file(&name, record)
        });
        if retained.is_err()
            && let Err(error) = Mappings::discard(&self.lock.state_dir().join("authority"))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(AdmissionError::DurableWrite);
        }
        retained
    }

    fn release_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        if record.binding() != &self.binding
            || record.pair().key.incarnation() != self.key.incarnation()
        {
            return Err(AdmissionError::Binding);
        }
        let owner = self.lock.check_authority_directory()?;
        let name = refusal_name(record.binding(), record.pair().key.incarnation());
        match Mappings::discard(&self.lock.state_dir().join(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                // `discard` also fails after its unlink, at the directory open or sync. The caller requests a
                // flip on this error and RetainedRefusal keeps the retention behind that refusal, so a marker
                // that is gone is recorded again; `retain_refusal` removes the local record when it cannot be.
                let kept = self.lock.retained_refusal(
                    owner,
                    record.binding(),
                    record.pair().key.incarnation(),
                );
                if !matches!(kept, Ok(true)) {
                    let _ = self.retain_refusal(record);
                }
                Err(AdmissionError::DurableWrite)
            }
            _ => Ok(()),
        }
    }
}
