//! The index's per-shard tables inside the index control mapping: the
//! bucket array, the chain summaries and the free stack, the gate and the
//! shard control record, plus one candidate scratch per registration record.
//!
//! Each enabled shard occupies a page-aligned run of the mapping laid out as
//! the geometry's extent describes: `B + A` buckets, `B` chain summaries,
//! one per base bucket, and `A` free-stack entries, then the gate and the
//! control record. Every value is
//! constructed in place before the storage owner exists and is trivially
//! dropped, so the owner unmaps the region directly. Only the gate holder
//! reads or writes the free stack's entries; its top is written under the
//! gate and sampled without it by reports. The scratch region is exclusive
//! to the registration that owns it, reached only through
//! `&mut Registration`.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::control::{ControlLayout, ControlLayoutOverflow, Field};
use super::gate::Gate;
use super::mapping::Mapping;
use super::os::Platform;
use super::owner::Storage;
use super::register::RegistrationIndex;
use crate::index::{
    Bucket, BucketRun, Identity, SHARD_CONTROL_ALIGN, SHARD_CONTROL_BYTES, ShardGeometry,
    ShardIndex, TERMINAL, ValidatedIndex,
};

/// The geometry charges the gate and the control record as one
/// [`SHARD_CONTROL_BYTES`] block; the two types together are exactly that.
const _: () = {
    assert!(size_of::<Gate>() + size_of::<ShardControl>() == SHARD_CONTROL_BYTES);
    assert!(align_of::<Gate>() == SHARD_CONTROL_ALIGN);
    assert!(align_of::<ShardControl>() == SHARD_CONTROL_ALIGN);
};

/// Fixed control words of one shard, written under the shard gate.
/// Failed gate attempts may update the statistics without the gate.
/// Two 128-byte blocks: the sequence alone in the first, the counters in the second.
/// Readers load only the sequence, so holder and failed-try writes stay off its line pair.
#[repr(C, align(128))]
pub(crate) struct ShardControl {
    /// The shard sequence; see `index::sequence`.
    pub sequence: AtomicU64,
    _line: [u8; 120],
    /// Visible keys `V`.
    pub visible: AtomicUsize,
    /// Claims for additional keys `P_index`: one per reserved fill, from
    /// its reservation until its publication's commit spends it or a
    /// refusal, a revocation or the fill service refunds it, plus one
    /// inside a test-only commit. A reservation compares `V + P_index`
    /// with `N`.
    pub reserved: AtomicUsize,
    /// Entries in the free stack: overflow buckets neither linked nor
    /// popped. Written under the gate, sampled by reports.
    pub free_top: AtomicUsize,
    /// Nonblocking gate attempts that found it busy or poisoned. Saturates
    /// at `usize::MAX`; a diagnostic that may undercount under contention.
    pub failed_tries: AtomicUsize,
    /// Admissions the shard can never grant: `N - V` at the terminal
    /// transition, zero while serving.
    pub lost_capacity: AtomicUsize,
}

/// Where one shard's tables live inside the index mapping.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShardImage {
    pub geometry: ShardGeometry,
    /// `B + A` buckets: base buckets first, then overflow buckets.
    buckets: Field<Bucket>,
    /// `B` chain summaries, one per base bucket.
    summaries: Field<AtomicU64>,
    /// `A` free-stack entries holding overflow indices.
    stack: Field<usize>,
    /// Overflow links a chain may follow, `D`.
    depth: usize,
    gate: Field<Gate>,
    control: Field<ShardControl>,
}

/// Every shard's image, the enabled shards' runs, the scratch region, and
/// the mapping extent.
#[derive(Debug)]
pub(crate) struct IndexImage {
    shards: Box<[Option<ShardImage>]>,
    /// Each enabled shard's bucket run, in enabled order, for the
    /// derivation's prefetch hint and a reader's tables.
    runs: Box<[BucketRun]>,
    /// `R * scratch_identities` identities; registration `r` owns entries
    /// `r * scratch_identities ..`.
    scratch: Field<Identity>,
    scratch_identities: usize,
    pub extent: usize,
}

impl IndexImage {
    /// Lays out every enabled shard on its own page boundary, then the
    /// scratch region, and rounds the whole to pages.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if any array or the running total is
    /// unrepresentable, or if an extent differs from the mapping-free
    /// inventory calculation.
    pub(crate) fn layout(
        index: &ValidatedIndex,
        readers: usize,
        page_size: usize,
    ) -> Result<Self, ControlLayoutOverflow> {
        let mut layout = ControlLayout::new();
        let mut shards = Vec::with_capacity(index.shards().len());
        let mut runs = Vec::with_capacity(index.enabled().len());
        for geometry in index.shards() {
            if !geometry.is_enabled() {
                shards.push(None);
                continue;
            }
            layout.align_to(page_size)?;
            let start = layout.size();
            let image = ShardImage {
                geometry: *geometry,
                buckets: layout.field::<Bucket>(geometry.base + geometry.overflow)?,
                summaries: layout.field::<AtomicU64>(geometry.base)?,
                stack: layout.field::<usize>(geometry.overflow)?,
                depth: index.depth(),
                gate: layout.field::<Gate>(1)?,
                control: layout.field::<ShardControl>(1)?,
            };
            layout.align_to(page_size)?;
            // The geometry's extent is the same layout computed without the
            // mapping, so the two agree or the configuration is refused.
            if layout.size() - start != geometry.extent {
                return Err(ControlLayoutOverflow);
            }
            runs.push(BucketRun {
                offset: image.buckets.offset(),
                summaries: image.summaries.offset(),
                bucket_mask: geometry.base - 1,
                buckets: image.buckets.len(),
                base: geometry.base,
                depth: image.depth,
                control: image.control.offset(),
            });
            shards.push(Some(image));
        }
        // Enabled shards are listed in shard order on both sides, so the
        // route hash selects the run of the shard it selects.
        debug_assert!(
            runs.len() == index.enabled().len()
                && runs
                    .iter()
                    .zip(index.enabled())
                    .all(|(run, enabled)| run.bucket_mask == enabled.bucket_mask)
        );
        let inventory = index.inventory();
        let scratch_identities = inventory.scratch_identities;
        let entries = readers
            .checked_mul(scratch_identities)
            .ok_or(ControlLayoutOverflow)?;
        let scratch = layout.field::<Identity>(entries)?;
        let extent = layout.extent(page_size)?;
        if extent != inventory.mapping_bytes {
            return Err(ControlLayoutOverflow);
        }
        Ok(Self {
            shards: shards.into_boxed_slice(),
            runs: runs.into_boxed_slice(),
            scratch,
            scratch_identities,
            extent,
        })
    }

    /// Writes every shard's tables and the scratch to their initial state:
    /// empty buckets with every overflow bucket on the free stack in index
    /// order; sequence zero, open gate, zero counters.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned, populated mapping this image was laid out for,
    /// the caller has exclusive access to the mapping, and every byte of this
    /// image's fields is still zero: [`Field::init`] relies on the mapping's
    /// zero fill for zero-valued elements.
    pub(crate) unsafe fn init(&self, mapping: &Mapping, blank: Identity) {
        for image in self.shards.iter().flatten() {
            let overflow = image.geometry.overflow;
            // SAFETY: forwarded from the caller for every field of one
            // mapping.
            unsafe {
                image.buckets.init(mapping, |_| Bucket::empty());
                image.summaries.init(mapping, |_| AtomicU64::new(0));
                // Stack entry `i` holds overflow index `A - 1 - i`, so the
                // first pop takes overflow bucket zero.
                image.stack.init(mapping, |entry| overflow - 1 - entry);
                image.gate.init(mapping, |_| Gate::open());
                image.control.init(mapping, |_| ShardControl {
                    sequence: AtomicU64::new(0),
                    _line: [0; 120],
                    visible: AtomicUsize::new(0),
                    reserved: AtomicUsize::new(0),
                    free_top: AtomicUsize::new(overflow),
                    failed_tries: AtomicUsize::new(0),
                    lost_capacity: AtomicUsize::new(0),
                });
            }
        }
        // SAFETY: as above.
        unsafe { self.scratch.init(mapping, |_| blank) };
    }

    pub(crate) fn shard(&self, shard: ShardIndex) -> Option<&ShardImage> {
        self.shards.get(shard.0)?.as_ref()
    }

    /// The enabled shards' bucket runs, for a derivation's prefetch hint and
    /// a reader's tables.
    pub(crate) fn runs(&self) -> &[BucketRun] {
        &self.runs
    }

    /// The control record and the arrays of the shard `run` describes, from
    /// the run alone: one record read after routing, where the shard image
    /// would take the enabled entry, the image and its fields in turn.
    ///
    /// # Safety
    ///
    /// `run` is an entry of this image's run table and `mapping` is the
    /// owned, initialized index mapping this image was laid out for, with no
    /// exclusive reference into the shard's tables: every shared field is an
    /// atomic.
    #[inline(always)]
    pub(crate) unsafe fn reader_tables<'m>(
        &self,
        mapping: &'m Mapping,
        run: &BucketRun,
    ) -> (&'m ShardControl, Tables<'m>) {
        debug_assert!(mapping.is_owned());
        debug_assert!(self.runs.iter().any(|entry| entry == run));
        let base = mapping.base().as_ptr();
        // SAFETY: the run copies the shard image's control and array fields,
        // which the layout placed inside the mapping the caller guarantees,
        // aligned and initialized before the owner existed.
        unsafe {
            let control = &*base.add(run.control).cast::<ShardControl>();
            let tables = Tables {
                buckets: std::slice::from_raw_parts(
                    base.add(run.offset).cast::<Bucket>(),
                    run.buckets,
                ),
                summaries: std::slice::from_raw_parts(
                    base.add(run.summaries).cast::<AtomicU64>(),
                    run.base,
                ),
                base: run.base,
                depth: run.depth,
            };
            (control, tables)
        }
    }

    /// Bytes of the run table and the placement records the image retains;
    /// the inventory counts the same bytes as `run_bytes + image_bytes`, and
    /// initialization charges them from there.
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.runs) + std::mem::size_of_val(&*self.shards)
    }

    /// Registration `reader`'s scratch: `scratch_identities` entries no other
    /// registration touches.
    ///
    /// # Safety
    ///
    /// `mapping` is the owned mapping this image was laid out for,
    /// [`init`](Self::init) has run, and `reader` is a position in the root
    /// image's registration records, which the same `reader_limit` sized, so
    /// the run lies inside the field. Dereferencing the result as `&mut`
    /// needs no other live reference into `reader`'s run; the caller's
    /// exclusive borrow of the registration is that exclusion.
    pub(crate) unsafe fn scratch(
        &self,
        mapping: &Mapping,
        reader: RegistrationIndex,
    ) -> NonNull<[Identity]> {
        let start = reader.0 * self.scratch_identities;
        debug_assert!(start + self.scratch_identities <= self.scratch.len());
        // SAFETY: `reader < R` and the field holds `R * scratch_identities`
        // entries, so the element pointer is in bounds and the run stays
        // within the field.
        unsafe {
            NonNull::slice_from_raw_parts(
                self.scratch.element_ptr(mapping, start),
                self.scratch_identities,
            )
        }
    }
}

/// One shard's buckets and chain summaries as a reader sees them, with what
/// its scan needs: the base bucket count `B` and depth `D`. [`Hold`] adds
/// the free stack, which only the gate holder touches.
pub(crate) struct Tables<'m> {
    /// `B + A` buckets: base buckets first, then overflow buckets.
    pub(crate) buckets: &'m [Bucket],
    /// `B` chain summaries, one per base bucket; see `index::summary`.
    pub(crate) summaries: &'m [AtomicU64],
    /// The base bucket count `B`, which is also the index of overflow
    /// bucket zero.
    pub(crate) base: usize,
    /// Overflow links a chain may follow, `D`.
    pub(crate) depth: usize,
}

/// One shard's arrays as the gate holder sees them: the buckets plus the
/// free stack, whose `&mut` only the gate holder forms. Only
/// [`ShardImage::hold`], under the gate, builds one.
pub(crate) struct Hold<'m> {
    /// `B + A` buckets: base buckets first, then overflow buckets.
    pub(crate) buckets: &'m [Bucket],
    /// `B` chain summaries, one per base bucket.
    pub(crate) summaries: &'m [AtomicU64],
    /// `A` free-stack entries; the entries below the control record's
    /// `free_top` hold the free overflow indices.
    pub(crate) stack: &'m mut [usize],
    /// Overflow links a chain may follow, `D`.
    pub(crate) depth: usize,
}

impl ShardImage {
    /// Every bucket, base first then overflow. Routed readers resolve the
    /// same view from the route's run through
    /// [`IndexImage::reader_tables`]; the close service's sweep, which
    /// addresses shards by index, and tests that plant and inspect a shard's
    /// buckets take it from the image.
    ///
    /// # Safety
    ///
    /// As for [`gate`](Self::gate).
    pub(crate) unsafe fn tables<'m>(&self, mapping: &'m Mapping) -> Tables<'m> {
        // SAFETY: the caller's guarantee is `as_slice`'s contract.
        unsafe {
            Tables {
                buckets: self.buckets.as_slice(mapping),
                summaries: self.summaries.as_slice(mapping),
                base: self.geometry.base,
                depth: self.depth,
            }
        }
    }

    /// The arrays for the gate holder, who alone forms the free stack's
    /// `&mut`.
    ///
    /// # Safety
    ///
    /// As for [`gate`](Self::gate), and the caller holds the shard gate for
    /// the whole `'m`: the gate is the only path that reads or writes the
    /// stack, so the `&mut` formed here is the only reference into it.
    #[inline(always)]
    pub(crate) unsafe fn hold<'m>(&self, mapping: &'m Mapping) -> Hold<'m> {
        // SAFETY: as for `gate`; the stack's exclusivity is the caller's
        // gate.
        unsafe {
            Hold {
                buckets: self.buckets.as_slice(mapping),
                summaries: self.summaries.as_slice(mapping),
                stack: &mut *self.stack.slice_ptr(mapping).as_ptr(),
                depth: self.depth,
            }
        }
    }

    /// The shard's buckets, for tests that plant and inspect them.
    ///
    /// # Safety
    ///
    /// As for [`tables`](Self::tables).
    #[cfg(test)]
    pub(crate) unsafe fn buckets<'m>(&self, mapping: &'m Mapping) -> &'m [Bucket] {
        // SAFETY: forwarded from the caller.
        unsafe { self.tables(mapping) }.buckets
    }

    /// The shard's chain summaries, for tests that inspect them.
    ///
    /// # Safety
    ///
    /// As for [`tables`](Self::tables).
    #[cfg(test)]
    pub(crate) unsafe fn summaries<'m>(&self, mapping: &'m Mapping) -> &'m [AtomicU64] {
        // SAFETY: forwarded from the caller.
        unsafe { self.tables(mapping) }.summaries
    }

    /// The shard's free stack, for tests that inspect it while no gate
    /// holder runs, so the `&mut` [`hold`](Self::hold) forms is the only
    /// reference into it.
    ///
    /// # Safety
    ///
    /// As for [`hold`](Self::hold).
    #[cfg(test)]
    pub(crate) unsafe fn stack<'m>(&self, mapping: &'m Mapping) -> &'m [usize] {
        // SAFETY: forwarded from the caller.
        unsafe { self.hold(mapping) }.stack
    }

    /// # Safety
    ///
    /// `mapping` is the owned mapping this image was laid out for and
    /// [`IndexImage::init`] has run; every shared field is an atomic and the
    /// padding is never read.
    #[inline(always)]
    pub(crate) unsafe fn gate<'m>(&self, mapping: &'m Mapping) -> &'m Gate {
        // SAFETY: the caller's guarantee is `as_slice`'s contract; one
        // element was laid out.
        unsafe { &self.gate.as_slice(mapping)[0] }
    }

    /// # Safety
    ///
    /// As for [`gate`](Self::gate).
    #[inline(always)]
    pub(crate) unsafe fn control<'m>(&self, mapping: &'m Mapping) -> &'m ShardControl {
        // SAFETY: as for `gate`; one element was laid out.
        unsafe { &self.control.as_slice(mapping)[0] }
    }
}

/// What one enabled shard reports about itself, read without its gate; the
/// counts are a sample while writers run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardReport {
    /// The sequence word: even and below the terminal value when stable;
    /// odd while a publication or an invalidation is between its two
    /// stores.
    pub sequence: u64,
    /// Whether the sequence reached its terminal value.
    pub terminal: bool,
    /// Visible keys `V`.
    pub visible: usize,
    /// Additional-key claims `P_index`: one per reserved fill, from its
    /// reservation until its publication's commit spends it or a refusal, a
    /// revocation or the fill service refunds it, plus one inside a
    /// test-only commit. A reservation compares `V + P_index` with `N`.
    pub reserved: usize,
    /// Overflow buckets on the free stack.
    pub free_overflow: usize,
    /// Gate attempts that found it busy or poisoned.
    pub failed_tries: usize,
    /// Admissions lost at the terminal transition.
    pub lost_capacity: usize,
}

impl<P: Platform> Storage<P> {
    /// What `shard` reports, or `None` for a disabled or unknown shard, no
    /// index or a drained owner.
    pub fn shard_report(&self, shard: ShardIndex) -> Option<ShardReport> {
        let index = self.index()?;
        let image = index.image.shard(shard)?;
        // SAFETY: the index mapping is owned and initialized while the
        // storage is live.
        let control = unsafe { image.control(&index.mapping) };
        // A sample: nothing is ordered after this load.
        let sequence = control.sequence.load(Ordering::Relaxed);
        Some(ShardReport {
            sequence,
            terminal: sequence == TERMINAL,
            visible: control.visible.load(Ordering::Relaxed),
            reserved: control.reserved.load(Ordering::Relaxed),
            free_overflow: control.free_top.load(Ordering::Relaxed),
            failed_tries: control.failed_tries.load(Ordering::Relaxed),
            lost_capacity: control.lost_capacity.load(Ordering::Relaxed),
        })
    }
}
