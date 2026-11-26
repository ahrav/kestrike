//! Copy-only test lenses over a live storage: the index's bindings, every
//! slot's facts, every held direct extent, and the verified key and payload
//! a record on raw media holds. Each lens copies into a caller's buffer, so
//! a warm window whose buffers keep their capacity allocates nothing, and
//! none takes a gate, a lease, a clock sample or a budget charge. A lens
//! that reads two fields of one slot sees one object's pair when every
//! earlier change to that slot happens before the call and every change
//! during the call runs on the calling thread. A lens
//! over a storage that is no longer live reports it rather than an empty
//! world.

use std::sync::atomic::Ordering;

use super::allocation::AllocationId;
use super::held::Held;
use super::layout::IO_UNIT;
use super::os::Platform;
use super::owner::Storage;
use super::record::{Crc32c, ExpectedHeader, ExtentPosition, RecordIdentity, verify_header};
use super::tables::SlotIndex;
use super::word;
use super::word::SlotState;
use crate::index::{Identity, ShardIndex};

/// One occupied index pair: its shard and the slot identity it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) shard: usize,
    pub(crate) identity: Identity,
}

/// One slot's record as it stands: its incarnation, whether a well-formed
/// word says `Resident` and holds a nonzero reference count (the anchor or
/// rights), the key hash its record stores, and its extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotFact {
    pub(crate) incarnation: u32,
    pub(crate) resident: bool,
    pub(crate) fingerprint: u64,
    pub(crate) session: u64,
    pub(crate) version: u64,
    pub(crate) device_unit: u64,
    pub(crate) len_units: u32,
}

impl SlotFact {
    /// The byte range of the slot's extent on the device, or `None` when it
    /// overflows the address space.
    pub(crate) fn media(&self) -> Option<std::ops::Range<usize>> {
        let start = usize::try_from(self.device_unit)
            .ok()?
            .checked_mul(IO_UNIT)?;
        let len = (self.len_units as usize).checked_mul(IO_UNIT)?;
        Some(start..start.checked_add(len)?)
    }
}

/// One slot's direct extent as device bytes, offset by the volume's metadata region, from a slot whose well-formed
/// word reads `Filling`, `Resident` or `Retired`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldExtent {
    pub(crate) holder: AllocationId,
    pub(crate) bytes: std::ops::Range<u64>,
}

/// The storage is no longer live: its lenses have nothing to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotLive;

pub(crate) fn live_resident(ident: u64) -> bool {
    word::well_formed(ident)
        && ident & word::STATE == SlotState::Resident.bits()
        && word::refs(ident) != 0
}

impl<P: Platform> Storage<P> {
    /// Copies every occupied index pair into `out`, shard, bucket and pair
    /// in order.
    pub(crate) fn bindings_into(&self, out: &mut Vec<Binding>) -> Result<(), NotLive> {
        out.clear();
        let index = self.index().ok_or(NotLive)?;
        for shard in 0..index.geometry.shards().len() {
            let Some(image) = index.image.shard(ShardIndex(shard)) else {
                continue;
            };
            // SAFETY: the index mapping is owned and initialized while the storage is live, which `index` checked.
            let buckets = unsafe { image.buckets(&index.mapping) };
            for bucket in buckets {
                out.extend(
                    bucket
                        .identities()
                        .map(|identity| Binding { shard, identity }),
                );
            }
        }
        Ok(())
    }

    /// Copies every slot's facts into `out`, in slot order. The state bits
    /// are read from the same word load as the count: a stopped boundary
    /// holds no gate, and a published object's slot stays `Resident` until
    /// the hold that unbinds it retires it.
    pub(crate) fn slot_facts_into(&self, out: &mut Vec<SlotFact>) -> Result<(), NotLive> {
        out.clear();
        let pool = self.live_pool().ok_or(NotLive)?;
        let metadata_units = pool.descriptor().geometry.metadata_units();
        let columns = pool.generations().iter().zip(pool.versions());
        out.extend(
            pool.records()
                .iter()
                .zip(columns)
                .map(|(record, (session, version))| {
                    let ident = record.ident.load(Ordering::Acquire);
                    let locator = record.locator();
                    SlotFact {
                        incarnation: word::incarnation(ident),
                        resident: live_resident(ident),
                        fingerprint: record.fingerprint(),
                        session: session.load(Ordering::Relaxed),
                        version: version.load(Ordering::Relaxed),
                        device_unit: metadata_units + locator.start_unit(),
                        len_units: locator.len_units(),
                    }
                }),
        );
        Ok(())
    }

    /// Copies every held direct extent into `out`, in slot order.
    ///
    /// The returned count adds one for each slot with a malformed word or an unrecognized state, and one for each
    /// slot whose word reads `Filling`, `Resident` or `Retired` with a locator that names a sequence block or decodes
    /// to nothing. A well-formed free or quarantined slot contributes zero regardless of its locator.
    ///
    /// For a well-formed `Filling`, `Resident` or `Retired` slot, the lens loads `ident` and the locator as two
    /// separate loads. The pair identifies one object when every earlier claim, restore and return of the slot
    /// happens before the call and every change during the call runs on the calling thread.
    pub(crate) fn held_extents_into(&self, out: &mut Vec<HeldExtent>) -> Result<u64, NotLive> {
        out.clear();
        let pool = self.live_pool().ok_or(NotLive)?;
        let geometry = pool.descriptor().geometry;
        let (metadata_units, payload_units) = (geometry.metadata_units(), geometry.payload_units());
        let mut unlisted = 0;
        for (slot, record) in pool.records().iter().enumerate() {
            let ident = record.ident.load(Ordering::Acquire);
            let state = ident & word::STATE;
            if !word::well_formed(ident) || state > SlotState::Quarantined.bits() {
                unlisted += 1;
                continue;
            }
            if state == SlotState::Free.bits() || state == SlotState::Quarantined.bits() {
                continue;
            }
            match Held::decode(record.locator()) {
                Some(Held::Direct(locator))
                    if locator.len_units() > 0
                        && locator.start_unit() + u64::from(locator.len_units())
                            <= payload_units =>
                {
                    let start = (metadata_units + locator.start_unit()) * IO_UNIT as u64;
                    let len = u64::from(locator.len_units()) * IO_UNIT as u64;
                    out.push(HeldExtent {
                        holder: AllocationId::new(SlotIndex(slot), word::incarnation(ident)),
                        bytes: start..start + len,
                    });
                }
                Some(_) | None => unlisted += 1,
            }
        }
        Ok(unlisted)
    }

    /// The key and the payload, metadata then body, of the record that
    /// starts `media`, the whole extent of the slot `allocation` names, with
    /// the length of the metadata its header frames, once that header
    /// verifies against the allocation and `session` and every chunk matches
    /// its checksum; `None` when any of that fails.
    pub(crate) fn record_payload<'m>(
        &self,
        media: &'m [u8],
        allocation: u64,
        fact: &SlotFact,
        session: u64,
    ) -> Option<([u8; 32], u32, &'m [u8])> {
        let (key, _, metadata, body) = super::record::framing(media)?;
        let expected = ExpectedHeader {
            position: ExtentPosition::FIRST,
            identity: RecordIdentity {
                key,
                allocation,
                session: fact.session,
                version: fact.version,
            },
            reader: session,
            len_units: u32::try_from(media.len() / IO_UNIT).ok()?,
            lengths: None,
        };
        let crc = Crc32c::detect();
        let verified = verify_header(crc, &self.record, media, &expected).ok()?;
        let layout = self.record.layout(metadata, body);
        let start = layout.header_bytes();
        let len = metadata as usize + body as usize;
        let payload = media.get(start..start.checked_add(len)?)?;
        // Chunk ranges count payload bytes, from the payload's first byte.
        for index in 0..layout.chunk_count() {
            let range = layout.chunk(index)?;
            let chunk = payload.get(range.start as usize..range.end as usize)?;
            verified.verify_chunk(crc, index, chunk).ok()?;
        }
        Some((key, metadata, payload))
    }

    /// The shard, tag and fingerprint `key` routes to in this storage's
    /// index, charging no budget, or `None` when the storage has no live
    /// index.
    pub(crate) fn fingerprint_of(&self, key: &[u8; 32]) -> Option<(usize, u16, u64)> {
        let route = self.route(key)?;
        Some((route.shard().0, route.tag(), route.fingerprint()))
    }
}
