//! The status codec: big-endian values at fixed offsets within each zone part, a decoder that accepts exactly the
//! encodings its encoder produces, the writer that seals statuses and the reader that accepts them.

use core::num::NonZeroU64;
use std::collections::BTreeMap;

use super::part::{
    ATTACHES, BLOCKERS, CLASSES, CLOSED, CREATES, Class, DECISIONS, ENROLLMENTS, ExceptionRow,
    Flags, GENERATION_MAX, HEALTHS, NEEDS, OUTCOMES, RECEIPTS, RECLAIMS, REFUSED, RESERVATIONS,
    STANDBYS, STEP_ERRORS, STORE_ALARMS, Standby, VERDICTS, ZonePart,
};
use super::{MAX_ROWS, MAX_ZONES, ROW_LEN, ReconcilerStatus, SCHEMA};
use crate::entropy::{EntropyError, nonce_from, os_entropy};
use crate::failover::assignment::hmac;
use crate::failover::records::ATTEMPTS_MAX;
use crate::failover::records::{Host, Reader as Bytes};
use crate::failover::report::{
    Envelope, KeptBoot, Members, ReportError, SealError, WriterId, admit, authenticated, field,
    flag, flagged, take_writer,
};
use crate::failover::standbys::{MAX_SLOTS, Zone};
use crate::failover::zone_loop::directory::MAX_HOSTS;
use crate::net::ownership::Shard;

const MAGIC: &[u8; 4] = b"RSTS";
const DOMAIN: &[u8; 16] = b"ebs-recon-status";
const KEY_DOMAIN: &[u8] = b"ebs-recon-status-key";
/// The 4-byte counts of a part: seven classes, the stale count, five standby states, two needs, seventeen
/// blockers, four attach counts, five closed causes, four receipt and four volume counts, four verdicts, the
/// self-suspect count, four store outcomes, the event counts and the omitted count.
const COUNTS: usize = CLASSES.len()
    + 1
    + (STANDBYS.len() - 1)
    + NEEDS
    + BLOCKERS
    + 4
    + CLOSED
    + RECEIPTS.len()
    + HEALTHS
    + VERDICTS
    + 1
    + OUTCOMES
    + REFUSED.len()
    + RESERVATIONS.len()
    + ENROLLMENTS.len()
    + DECISIONS.len()
    + STEP_ERRORS.len()
    + CREATES.len()
    + ATTACHES.len()
    + RECLAIMS.len()
    + 1;
/// The zone (2), the tick (8), the flags (1), the counts, the flagged stale age and the flagged count of unnamed
/// volumes (9 each), five pairs of 17 bytes (the census, the pairs, the silent hosts and the two budgets), the store
/// alarm (1) and the row count (1).
pub(super) const PART_LEN: usize = 2 + 8 + 1 + 4 * COUNTS + 2 * 9 + 5 * 17 + 1 + 1;

const _: () = assert!(PART_LEN == 548 && ROW_LEN == 14 && super::MAX_LEN == 16_016);

/// The key that authenticates one reconciler's statuses. It has no `Debug`, so no format string prints it. A key
/// from [`StatusKey::derive`] lies in its own HMAC domain, so no host report key derived from the same secret
/// verifies a status.
#[derive(Clone, Copy)]
pub struct StatusKey(pub [u8; 32]);

impl StatusKey {
    /// The status key of `reconciler_key` authenticates statuses in an HMAC domain of their own.
    pub fn derive(reconciler_key: &[u8; 32]) -> Self {
        Self(hmac(reconciler_key, &[KEY_DOMAIN]))
    }
}

/// Moves a part's fields between the part and its bytes in wire order: the encoder reads each field and appends
/// its bytes, and the decoder reads the bytes, checks them and writes the field.
trait Fields {
    fn bytes<const N: usize>(&mut self, value: &mut [u8; N]) -> Result<(), ReportError>;

    fn counts(&mut self, counts: &mut [u32]) -> Result<(), ReportError> {
        for count in counts {
            let mut bytes = count.to_be_bytes();
            self.bytes(&mut bytes)?;
            *count = u32::from_be_bytes(bytes);
        }
        Ok(())
    }

    fn count(&mut self, count: &mut u32) -> Result<(), ReportError> {
        self.counts(core::slice::from_mut(count))
    }

    fn u64(&mut self, value: &mut u64) -> Result<(), ReportError> {
        let mut bytes = value.to_be_bytes();
        self.bytes(&mut bytes)?;
        *value = u64::from_be_bytes(bytes);
        Ok(())
    }

    /// A flag byte then an 8-byte value: a flag other than 0 and 1, or a clear flag with a nonzero value, refuses
    /// as a flag.
    fn flagged(&mut self, value: &mut Option<u64>) -> Result<(), ReportError> {
        let mut present = [u8::from(value.is_some())];
        let mut held = value.unwrap_or(0);
        self.bytes(&mut present)?;
        self.u64(&mut held)?;
        *value = flagged(present[0], held)?;
        Ok(())
    }

    /// A flag byte, `used` and `limit`: a flag other than 0 and 1, or a clear flag with a nonzero value, refuses as
    /// a flag, and a set flag refuses as a field when `used` exceeds `limit`.
    fn members(&mut self, members: &mut Members) -> Result<(), ReportError> {
        self.pair(members)?;
        field(!matches!(*members, Members::Known { used, limit } if used > limit))
    }

    /// A flag byte, `used` and `limit` read as independent values: the census length beside its configured cap,
    /// which a cap lowered below a census already written leaves below the length, and the zone's recorded pairs
    /// beside its summed pair cap, which reads below the pairs only when the zone's pairs exceed the summed cap. A flag other than
    /// 0 and 1, or a clear flag with a nonzero value, refuses as a flag.
    fn pair(&mut self, members: &mut Members) -> Result<(), ReportError> {
        let (mut present, mut used, mut limit) = match *members {
            Members::Unavailable => ([0], 0, 0),
            Members::Known { used, limit } => ([1], used, limit),
        };
        self.bytes(&mut present)?;
        self.u64(&mut used)?;
        self.u64(&mut limit)?;
        flag(present[0] == 1 || (present[0] == 0 && used == 0 && limit == 0))?;
        *members = match present[0] {
            1 => Members::Known { used, limit },
            _ => Members::Unavailable,
        };
        Ok(())
    }

    /// The code byte of a label in `table`, which has no absent code; a code past the table refuses as a flag, and
    /// the encoder writes a value `table` lacks as 255.
    fn label<T: Copy + PartialEq>(
        &mut self,
        table: &[T],
        value: &mut T,
    ) -> Result<(), ReportError> {
        let at = table.iter().position(|listed| listed == value);
        let mut code = [at.map_or(u8::MAX, |at| at as u8)];
        self.bytes(&mut code)?;
        let at = usize::from(code[0]);
        flag(at < table.len())?;
        *value = table[at];
        Ok(())
    }
}

/// Appends each field's bytes.
struct Put<'a>(&'a mut Vec<u8>);

impl Fields for Put<'_> {
    fn bytes<const N: usize>(&mut self, value: &mut [u8; N]) -> Result<(), ReportError> {
        self.0.extend_from_slice(value);
        Ok(())
    }
}

/// Reads each field's bytes; a read past the body refuses as a length.
struct Take<'a, 'b>(&'b mut Bytes<'a>);

impl Fields for Take<'_, '_> {
    fn bytes<const N: usize>(&mut self, value: &mut [u8; N]) -> Result<(), ReportError> {
        *value = self.0.take()?;
        Ok(())
    }
}

/// The flags in bit order: bit `k` is flag `k` of the contract's table.
fn flag_bits(flags: &mut Flags) -> [&mut bool; 8] {
    [
        &mut flags.reports,
        &mut flags.instances,
        &mut flags.volumes,
        &mut flags.store,
        &mut flags.warm_up,
        &mut flags.zone_host,
        &mut flags.operator,
        &mut flags.cap_below,
    ]
}

/// Moves every field of `part` but its rows, then the row count, in wire order.
fn fields(part: &mut ZonePart, f: &mut impl Fields) -> Result<(), ReportError> {
    let mut zone = part.zone.0.to_be_bytes();
    f.bytes(&mut zone)?;
    part.zone = Zone(u16::from_be_bytes(zone));
    f.u64(&mut part.tick)?;
    let bits = flag_bits(&mut part.flags);
    let mut byte =
        [(bits.iter().enumerate()).fold(0, |byte, (at, bit)| byte | (u8::from(**bit) << at))];
    f.bytes(&mut byte)?;
    for (at, bit) in bits.into_iter().enumerate() {
        *bit = byte[0] & (1 << at) != 0;
    }
    f.counts(&mut part.classes)?;
    f.count(&mut part.stale_serving)?;
    f.flagged(&mut part.stale_oldest_us)?;
    f.counts(&mut part.standby)?;
    f.counts(&mut part.needs)?;
    f.counts(&mut part.blockers)?;
    f.pair(&mut part.census)?;
    field(within(part.census, MAX_SLOTS as u64))?;
    let a = &mut part.attaches;
    for count in [
        &mut a.live,
        &mut a.ended_paired,
        &mut a.ended_unpaired,
        &mut a.gone,
    ] {
        f.count(count)?;
    }
    f.pair(&mut a.pairs)?;
    f.counts(&mut a.closed)?;
    f.counts(&mut part.receipts)?;
    f.counts(&mut part.volumes)?;
    f.flagged(&mut part.unnamed_volumes)?;
    f.counts(&mut part.hosts.verdicts)?;
    f.members(&mut part.hosts.silent)?;
    field(within(part.hosts.silent, MAX_HOSTS as u64))?;
    f.count(&mut part.hosts.self_suspect)?;
    f.members(&mut part.budgets.attempts)?;
    field(limit_is(part.budgets.attempts, u64::from(ATTEMPTS_MAX)))?;
    f.members(&mut part.budgets.generation)?;
    field(limit_is(part.budgets.generation, GENERATION_MAX))?;
    f.label(STORE_ALARMS, &mut part.store.alarm)?;
    f.counts(&mut part.store.outcomes)?;
    let e = &mut part.events;
    for counts in [
        &mut e.refused[..],
        &mut e.reservations,
        &mut e.enrollments,
        &mut e.decisions,
        &mut e.errors,
        &mut e.creates,
        &mut e.attaches,
        &mut e.reclaims,
    ] {
        f.counts(counts)?;
    }
    f.count(&mut part.omitted)
}

/// Whether a known `members` reads `used` and `limit` each at most `max`; an unavailable one holds.
fn within(members: Members, max: u64) -> bool {
    match members {
        Members::Known { used, limit } => used <= max && limit <= max,
        Members::Unavailable => true,
    }
}

/// Whether a known `members` reads `limit` as its limit; an unavailable one holds.
fn limit_is(members: Members, limit: u64) -> bool {
    match members {
        Members::Known { limit: held, .. } => held == limit,
        Members::Unavailable => true,
    }
}

/// Moves one row's fields in wire order.
fn row_fields(row: &mut ExceptionRow, f: &mut impl Fields) -> Result<(), ReportError> {
    let mut shard = row.shard.get();
    f.count(&mut shard)?;
    f.label(CLASSES, &mut row.class)?;
    f.label(STANDBYS, &mut row.standby)?;
    f.u64(&mut row.age_us)?;
    row.shard = Shard::new(shard).ok_or(ReportError::Field)?;
    field(ExceptionRow::admits(row.class, row.standby))
}

/// Appends the bytes of `part`, its rows included.
fn put_part(out: &mut Vec<u8>, part: &ZonePart) {
    let mut part = part.clone();
    let mut put = Put(out);
    // A check that fails stops the encoding at its field, and the writer's decode of the body reports it as
    // `SealError::Field`.
    let _ = fields(&mut part, &mut put);
    // `StatusWriter::seal` refuses a zone of more than `MAX_ROWS` rows before it encodes one.
    put.0.push(part.rows.len() as u8);
    for row in &mut part.rows {
        let _ = row_fields(row, &mut put);
    }
}

/// Decodes one part, its rows included.
///
/// # Errors
///
/// The first failing check in wire order: flags and members within their rules and labels within their tables; then,
/// after every field, a stale age present exactly when the stale count is nonzero; then at most [`MAX_ROWS`] rows, an omitted count only beside
/// [`MAX_ROWS`] rows, and rows of distinct nonzero shards that [`ExceptionRow::admits`] names, ordered by descending
/// age and then ascending shard.
fn take_part(r: &mut Bytes<'_>) -> Result<ZonePart, ReportError> {
    let mut part = ZonePart::blank(Zone(0));
    let mut take = Take(r);
    fields(&mut part, &mut take)?;
    field((part.stale_oldest_us.is_some()) == (part.stale_serving > 0))?;
    let count = usize::from(take.0.u8()?);
    field(count <= MAX_ROWS && (part.omitted == 0 || count == MAX_ROWS))?;
    let placeholder = ExceptionRow {
        shard: Shard::new(1).expect("1 is a shard"),
        class: Class::Silent,
        standby: Standby::Unknown,
        age_us: 0,
    };
    for _ in 0..count {
        let mut row = placeholder;
        row_fields(&mut row, &mut take)?;
        let ordered = part.rows.last().is_none_or(|last| {
            last.age_us > row.age_us || (last.age_us == row.age_us && last.shard < row.shard)
        });
        field(ordered && part.rows.iter().all(|seen| seen.shard != row.shard))?;
        part.rows.push(row);
    }
    Ok(part)
}

/// Decodes a body: the header after the writer, then each part.
///
/// # Errors
///
/// The first failing check in layout order: a zero sequence, a nonzero header pad, a zone count above
/// [`MAX_ZONES`], each part's checks, zones out of ascending order, and bytes left after the last part.
fn decode(body: &[u8]) -> Result<ReconcilerStatus, ReportError> {
    let mut r = Bytes::open(body, MAGIC, SCHEMA)?;
    let writer = take_writer(&mut r)?;
    let sequence = r.u64()?;
    field(sequence >= 1)?;
    let sealed_at_us = r.u64()?;
    let (count, zero) = (usize::from(r.u8()?), r.u8()?);
    flag(zero == 0)?;
    if count > MAX_ZONES {
        return Err(ReportError::Length);
    }
    let mut zones: Vec<ZonePart> = Vec::with_capacity(count);
    for _ in 0..count {
        let part = take_part(&mut r)?;
        field(zones.last().is_none_or(|last| last.zone < part.zone))?;
        zones.push(part);
    }
    if !r.0.is_empty() {
        return Err(ReportError::Length);
    }
    Ok(ReconcilerStatus {
        writer,
        sequence,
        sealed_at_us,
        zones,
    })
}

/// Seals one reconciler's statuses under its status key, at most one per period, with sequences from 1.
pub struct StatusWriter {
    key: StatusKey,
    envelope: Envelope,
}

impl core::fmt::Debug for StatusWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatusWriter")
            .field("envelope", &self.envelope)
            .finish_non_exhaustive()
    }
}

impl StatusWriter {
    /// A writer for the reconciler `identity` under `key` and a boot nonce drawn from the operating system. The
    /// caller makes a new writer whenever it starts a zone loop or a store client whose counts the status carries,
    /// so the counts of one boot belong to one run of each loop.
    ///
    /// # Errors
    ///
    /// The draw's error.
    pub fn new(
        identity: Host,
        key: StatusKey,
        period_us: NonZeroU64,
    ) -> Result<Self, EntropyError> {
        let boot = nonce_from(os_entropy)?;
        Ok(Self {
            key,
            envelope: Envelope::new(
                WriterId {
                    host: identity,
                    boot,
                },
                period_us,
            ),
        })
    }

    /// Seals the next status of `zones`, given in ascending zone order, then advances the sequence and the next due
    /// time. `sealed_at_us` and `elapsed_us` stamp and pace the status as [`super::super::Writer::seal`] does.
    ///
    /// # Errors
    ///
    /// [`SealError::Early`] before [`SealError::Entries`], for more than [`MAX_ZONES`] zones or a zone with more
    /// than [`MAX_ROWS`] rows, before [`SealError::Exhausted`] before [`SealError::Field`], which names the
    /// decoder's refusal of the encoding.
    pub fn seal(
        &mut self,
        zones: &[ZonePart],
        sealed_at_us: u64,
        elapsed_us: u64,
    ) -> Result<Vec<u8>, SealError> {
        let fits = zones.len() <= MAX_ZONES && zones.iter().all(|zone| zone.rows.len() <= MAX_ROWS);
        let slot = self.envelope.slot(fits, sealed_at_us, elapsed_us)?;
        let mut body = Vec::with_capacity(super::MAX_LEN);
        body.extend_from_slice(&self.envelope.header(MAGIC, SCHEMA, slot, zones.len()));
        for part in zones {
            put_part(&mut body, part);
        }
        decode(&body).map_err(SealError::Field)?;
        Ok(self.envelope.close(&self.key.0, DOMAIN, body, slot))
    }
}

/// Accepts statuses, keeping for each writer up to `BOOTS` boots with their sequence and seal-time high-waters.
#[derive(Debug, Default)]
pub struct StatusReader {
    seen: BTreeMap<Host, Vec<KeptBoot>>,
}

impl StatusReader {
    /// Authenticates and decodes `bytes` under the status key `key` returns for the writer, and records the
    /// sequence. `key` receives the unauthenticated header writer, so it must be a bounded local lookup. The reader's
    /// state changes only on an accepted status.
    ///
    /// # Errors
    ///
    /// In order: [`ReportError::Length`] under 6 bytes, [`ReportError::Magic`], [`ReportError::Schema`] before any
    /// later field is read, [`ReportError::Length`] over [`super::MAX_LEN`] or under the header and tag,
    /// [`ReportError::Writer`], [`ReportError::Tag`], the body's checks in layout order, then
    /// [`ReportError::Duplicate`].
    pub fn accept(
        &mut self,
        bytes: &[u8],
        key: impl FnOnce(Host) -> Option<StatusKey>,
    ) -> Result<ReconcilerStatus, ReportError> {
        let layout = |bytes: &[u8]| match bytes.len() > super::MAX_LEN {
            true => Err(ReportError::Length),
            false => Ok(()),
        };
        let key = |host| key(host).map(|key| key.0);
        let body = authenticated(bytes, (MAGIC, SCHEMA, DOMAIN), layout, key)?;
        let status = decode(body)?;
        admit(
            &mut self.seen,
            status.writer,
            status.sequence,
            status.sealed_at_us,
        )?;
        Ok(status)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A writer whose boot and first sequence the test fixes.
    pub(crate) fn fixed(
        identity: Host,
        boot: [u8; 16],
        key: StatusKey,
        period_us: NonZeroU64,
    ) -> StatusWriter {
        StatusWriter {
            key,
            envelope: Envelope::new(
                WriterId {
                    host: identity,
                    boot,
                },
                period_us,
            ),
        }
    }
}
