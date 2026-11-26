//! Per-shard bucket geometry, chain and scratch bounds and the byte
//! inventory derived from a validated index configuration.
//!
//! Every quantity is derived with checked products, ceiling division and
//! power-of-two rounding; a value that does not fit `usize` or `isize` is a
//! distinct typed refusal, never a wrap. No default shard count, load factor
//! or overflow ratio exists: every limit is caller input. Geometry and load
//! factor promise bounded work per key, not collision-free admission: a
//! chain that fills at its depth bound refuses even while other shards have
//! room.
//!
//! For each shard with visible limit `N`, load `a/b`, overflow ratio `r/t`
//! and depth `D`:
//!
//! - base buckets `B = next_power_of_two(max(1, ceil(N * b / (14 * a))))`,
//!   each with one 64-bit chain summary;
//! - overflow buckets `A = ceil(N * r / (14 * t))`;
//! - physical pairs `T = 14 * (B + A)`;
//! - a complete chain examines at most `14 * (1 + D)` pairs, which is also
//!   the candidate scratch capacity in identities.
//!
//! The batch width limit `BatchMax` is caller input carried through
//! validation unchanged; no value is refused. A batch reuses the scalar
//! scratch element by element, so the scratch size depends on `D` alone.
//!
//! The fill-authority tables sized by `F[s]` live in the root control mapping.
//! The storage owner derives that mapping's layout from these values, so validation proves each shard's record arrays fit `isize::MAX` first.
//! A shard with `F = 0` has no table and admits no fill.
//! Bucket geometry is a function of `N`, the load and overflow ratios and
//! the page size alone.
//!
//! A shard whose `N` is zero is disabled: it has no arrays and routing never
//! selects it. The base load `N / (14 * B)` and the physical load `N / T` are
//! reported separately: they differ by the overflow reserve `A`. Rounding
//! `B` up to a power of two keeps the base load, and so the physical load,
//! at most the configured `a / b`.

use std::alloc::Layout;
use std::sync::atomic::AtomicU64;

use super::bucket::{Bucket, Identity, PAIRS};
use super::hash::{BucketRun, HASH_STATE_BYTES, Key};
use crate::storage::{FillImage, ShardImage, ValidatedConfig};

/// Position of a shard in the configured shard list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardIndex(pub usize);

/// A rational `numerator / denominator` as caller input or reported load.
/// Equality is representational: `1/2` and `2/4` are different values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    pub numerator: usize,
    pub denominator: usize,
}

/// How the visible capacity is split over shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardLimits<'a> {
    /// One visible limit `N[s]` per shard, in shard order.
    Explicit(&'a [usize]),
    /// `total` split evenly over `shards` shards, the first `total % shards`
    /// shards taking one more, so the split is the same on every run.
    Even { shards: usize, total: usize },
}

/// Unvalidated index configuration. Every field is a required caller input;
/// the page size, object slot counts and reader limit come from the storage
/// configuration the index is validated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexConfig<'a> {
    pub shards: ShardLimits<'a>,
    /// Target base load `a / b` with `0 < a < b`.
    pub load: Ratio,
    /// Overflow reserve `r / t` with `r >= 0` and `t > 0`.
    pub overflow: Ratio,
    /// Overflow links a chain may follow, `D`. Zero confines every key to
    /// its base bucket; a value whose scratch `14 * (1 + D)` does not fit is
    /// refused. A chain links at most its shard's `A` overflow buckets, so a
    /// value above `A` adds no capacity there, while the scratch and every
    /// prepaid walk bound still grow with `D`.
    pub depth: usize,
    /// Widest batch a registered reader may pass, `BatchMax`. Zero admits
    /// only the empty batch.
    pub batch_max: usize,
    /// Fill-authority records `F[s]` per shard, in shard order; zero admits no fill on that shard.
    ///
    /// Each fill BEGIN, a PUT's or a local fill's through `Storage::begin_fill`, draws one record from its key's shard and refuses `FillSlotsFull` when that shard holds none Free, whatever the other shards hold.
    /// A record stays occupied from its grant until fill service frees it, after its owner departs.
    /// Owner start checks the pooled capacity `min(sum(F[s]), lease_limit / 2)` against `puts`: the record term `puts <= sum(F[s])` is necessary for every BEGIN at the PUT cap to find a record, and the lease term `lease_limit / 2` bounds the fills reserved at once.
    ///
    /// A sizing model places the keys of `L + D` occupied records independently and uniformly on `S` enabled shards of `fills` records each.
    /// `L` counts the other live attempts holding a record: at most `puts - 1` PUTs, run-waiters included, plus every local fill until fill service frees its record; `D` counts departed records awaiting release by fill service.
    /// Under that model a BEGIN at the PUT cap finds its shard full with probability `P(Bin(L + D, 1/S) >= fills)`.
    /// Admission caps each shard's occupied records at `fills`, and records for the same key share a shard.
    /// Size `fills` as the smallest value that meets the target probability at the largest `D` the deployment expects: with 256 PUTs, no concurrent local fills, 16 shards and a target of `1e-3`, that is 30 at `D = 0` and 32 for `D` up to 29.
    /// At 16 records per shard and `D = 0` the model gives 0.53.
    /// The probability applies to one BEGIN at the PUT cap, for its own shard; the target is a per-BEGIN bound, and a run-level refusal ratio is a separate measurement.
    pub fills: &'a [usize],
}

/// Why an [`IndexConfig`] is rejected. Each variant is a distinct refusal
/// and the refused input is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryError {
    /// `shards` names no shard.
    NoShards,
    /// The per-shard geometry tables for `shards` shards do not fit
    /// `isize::MAX`.
    ShardTableOverflow { shards: usize },
    /// `load` is not `0 < a < b`.
    InvalidLoad(Ratio),
    /// `overflow` has a zero denominator.
    InvalidOverflow(Ratio),
    /// `sum N[s]` does not fit `usize`.
    VisibleOverflow,
    /// `sum N[s]` exceeds the object slots `O` the volume holds.
    VisibleExceedsSlots { visible: usize, slots: usize },
    /// The scratch identity count, `14 * (1 + D)`, does not fit `usize`.
    ScratchOverflow { depth: usize },
    /// The scratch does not fit `isize::MAX`.
    ScratchLayoutOverflow { depth: usize },
    /// A product or sum for `shard` does not fit `usize`.
    Overflow { shard: ShardIndex },
    /// A shard's arrays do not fit `isize::MAX`.
    LayoutOverflow { shard: ShardIndex },
    /// The whole-index byte total does not fit `usize`.
    InventoryOverflow,
    /// `fills` has `fills` entries where the shard list has `shards`; one `F` per configured shard is required.
    FillShape { shards: usize, fills: usize },
    /// A disabled shard, `N = 0`, is given a nonzero `F`.
    FillOnDisabledShard { shard: ShardIndex },
    /// `shard`'s fill record arrays do not fit `isize::MAX`.
    FillLayoutOverflow { shard: ShardIndex },
}

/// One shard's checked geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardGeometry {
    /// Visible limit `N`; zero for a disabled shard.
    pub visible: usize,
    /// Base buckets `B`; a power of two, or zero when disabled.
    pub base: usize,
    /// Preallocated overflow buckets `A`.
    pub overflow: usize,
    /// Usable pair capacity `T = 14 * (B + A)`.
    pub physical: usize,
    /// Bytes of the shard's buckets, chain summaries, free stack and fixed
    /// control record, rounded to whole pages.
    pub extent: usize,
}

impl ShardGeometry {
    const DISABLED: Self = Self {
        visible: 0,
        base: 0,
        overflow: 0,
        physical: 0,
        extent: 0,
    };

    pub fn is_enabled(&self) -> bool {
        self.visible != 0
    }

    /// Mask that selects the base bucket from a hash, `B - 1`; `None` for a
    /// disabled shard, which has no buckets.
    pub fn bucket_mask(&self) -> Option<usize> {
        self.base.checked_sub(1)
    }

    /// Visible keys per base pair, `N / (14 * B)`; `None` when disabled.
    pub fn base_load(&self) -> Option<Ratio> {
        self.is_enabled().then(|| Ratio {
            numerator: self.visible,
            denominator: PAIRS * self.base,
        })
    }

    /// Visible keys per physical pair, `N / T`; `None` when disabled.
    pub fn physical_load(&self) -> Option<Ratio> {
        self.is_enabled().then_some(Ratio {
            numerator: self.visible,
            denominator: self.physical,
        })
    }
}

/// One shard routing may select, with the mask its base bucket is chosen by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnabledShard {
    pub shard: ShardIndex,
    /// `B[shard] - 1`.
    pub bucket_mask: usize,
}

/// Fixed per-shard control bytes charged beside the arrays.
/// Three 128-byte blocks: the gate, the sequence, and the free-stack top with the statistics.
/// The mutation owner's writes share no line with bucket reads, busy gate tries or sequence loads.
pub const SHARD_CONTROL_BYTES: usize = 384;

/// Alignment of the control blocks.
pub const SHARD_CONTROL_ALIGN: usize = 128;

/// Bytes of the whole index, reported for the engine ledger to charge
/// beside, and disjoint from, every storage charge; initialization charges
/// `total` and nothing else for the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexInventory {
    /// Sum of every enabled shard's page-rounded extent.
    pub shard_bytes: usize,
    /// Extent of the index mapping: the shard runs, then every participant's
    /// scratch, rounded up to whole pages and at least one page.
    pub mapping_bytes: usize,
    /// Bytes of the geometry tables the validated index retains: one
    /// `ShardGeometry` per shard, one `EnabledShard` per enabled shard and
    /// one `usize` fill count per shard.
    pub geometry_bytes: usize,
    /// Bytes of the keyed hash state.
    pub hash_state_bytes: usize,
    /// Bytes of the bucket runs the index image retains for the derivation's
    /// prefetch hint and a reader's tables: one record per enabled shard.
    pub run_bytes: usize,
    /// Bytes of the placement records the index image retains: one per
    /// configured shard, enabled or not.
    pub image_bytes: usize,
    /// Identities one candidate scratch holds: `14 * (1 + D)`.
    pub scratch_identities: usize,
    /// Bytes of one participant's candidate scratch.
    pub scratch_bytes: usize,
    /// Participants charged one scratch each: the reader limit `R`.
    pub participants: usize,
    /// `mapping_bytes + geometry_bytes + hash_state_bytes + run_bytes +
    /// image_bytes`.
    pub total: usize,
}

/// A configuration that passed [`IndexConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIndex {
    shards: Box<[ShardGeometry]>,
    /// The enabled shards in shard order; routing reduces a hash into this
    /// list so a disabled shard is never selected.
    enabled: Box<[EnabledShard]>,
    depth: usize,
    batch_max: usize,
    /// `F[s]` per shard, in shard order; zero for a shard without a table.
    fills: Box<[usize]>,
    /// The largest `F[s]`, zero without any table, so a per-call bound over
    /// any shard's table is a read, not a pass over the shards.
    fill_max: usize,
    inventory: IndexInventory,
}

impl IndexConfig<'_> {
    /// Checks every invariant in the module documentation against the
    /// storage configuration's page size, object slot counts and reader
    /// limit, and derives every shard's geometry and the byte inventory.
    ///
    /// # Errors
    ///
    /// Returns `GeometryError` variants in this order: `NoShards`, `ShardTableOverflow`, `FillShape`, `InvalidLoad`, `InvalidOverflow`, `VisibleOverflow`, `VisibleExceedsSlots`, `ScratchOverflow`, `ScratchLayoutOverflow`; then, per shard in index order, `FillOnDisabledShard`, `FillLayoutOverflow`, and for enabled shards `Overflow` and `LayoutOverflow`; returns `InventoryOverflow` when enabled extents so far or their final total do not fit `usize`.
    pub fn validate(&self, storage: &ValidatedConfig) -> Result<ValidatedIndex, GeometryError> {
        let count = match self.shards {
            ShardLimits::Explicit(limits) => limits.len(),
            ShardLimits::Even { shards, .. } => shards,
        };
        if count == 0 {
            return Err(GeometryError::NoShards);
        }
        if Layout::array::<ShardGeometry>(count).is_err()
            || Layout::array::<EnabledShard>(count).is_err()
            || Layout::array::<usize>(count).is_err()
        {
            return Err(GeometryError::ShardTableOverflow { shards: count });
        }
        if self.fills.len() != count {
            return Err(GeometryError::FillShape {
                shards: count,
                fills: self.fills.len(),
            });
        }
        let load = self.load;
        if load.numerator == 0 || load.numerator >= load.denominator {
            return Err(GeometryError::InvalidLoad(load));
        }
        if self.overflow.denominator == 0 {
            return Err(GeometryError::InvalidOverflow(self.overflow));
        }
        let visible = match self.shards {
            ShardLimits::Explicit(limits) => limits
                .iter()
                .try_fold(0usize, |sum, &limit| sum.checked_add(limit))
                .ok_or(GeometryError::VisibleOverflow)?,
            ShardLimits::Even { total, .. } => total,
        };
        // The slot count is validated storage input.
        let slots = storage.volume().slot_count;
        if visible > slots {
            return Err(GeometryError::VisibleExceedsSlots { visible, slots });
        }
        let depth = self.depth;
        let scratch_identities = depth
            .checked_add(1)
            .and_then(|links| links.checked_mul(PAIRS))
            .ok_or(GeometryError::ScratchOverflow { depth })?;
        let scratch_bytes = Layout::array::<Identity>(scratch_identities)
            .map_err(|_| GeometryError::ScratchLayoutOverflow { depth })?
            .size();

        let mut shards = Vec::with_capacity(count);
        let mut enabled = Vec::with_capacity(count);
        let mut shard_bytes = 0usize;
        for index in 0..count {
            let shard = ShardIndex(index);
            let visible = self.limit(index);
            let fills = self.fills[index];
            if visible == 0 && fills != 0 {
                return Err(GeometryError::FillOnDisabledShard { shard });
            }
            if Layout::array::<u64>(fills).is_err() || Layout::array::<Key>(fills).is_err() {
                return Err(GeometryError::FillLayoutOverflow { shard });
            }
            let geometry = self.shard_geometry(shard, visible, storage.page_size())?;
            if let Some(bucket_mask) = geometry.bucket_mask() {
                enabled.push(EnabledShard { shard, bucket_mask });
                shard_bytes = shard_bytes
                    .checked_add(geometry.extent)
                    .ok_or(GeometryError::InventoryOverflow)?;
            }
            shards.push(geometry);
        }
        let participants = storage.reader_limit();
        let geometry_bytes = std::mem::size_of_val(shards.as_slice())
            .checked_add(std::mem::size_of_val(enabled.as_slice()))
            .and_then(|sum| sum.checked_add(std::mem::size_of_val(self.fills)))
            .ok_or(GeometryError::InventoryOverflow)?;
        let run_bytes = enabled
            .len()
            .checked_mul(size_of::<BucketRun>())
            .ok_or(GeometryError::InventoryOverflow)?;
        let image_bytes = count
            .checked_mul(size_of::<Option<ShardImage>>() + size_of::<Option<FillImage>>())
            .ok_or(GeometryError::InventoryOverflow)?;
        // Round the mapping up to a page; an empty layout maps one page.
        let page_size = storage.page_size();
        let mapping_bytes = participants
            .checked_mul(scratch_bytes)
            .and_then(|scratch| scratch.checked_add(shard_bytes))
            .and_then(|bytes| bytes.checked_next_multiple_of(page_size))
            .map(|bytes| bytes.max(page_size))
            .ok_or(GeometryError::InventoryOverflow)?;
        let total = mapping_bytes
            .checked_add(geometry_bytes)
            .and_then(|sum| sum.checked_add(HASH_STATE_BYTES))
            .and_then(|sum| sum.checked_add(run_bytes))
            .and_then(|sum| sum.checked_add(image_bytes))
            .ok_or(GeometryError::InventoryOverflow)?;
        Ok(ValidatedIndex {
            shards: shards.into_boxed_slice(),
            enabled: enabled.into_boxed_slice(),
            depth,
            batch_max: self.batch_max,
            fills: self.fills.into(),
            fill_max: self.fills.iter().copied().max().unwrap_or(0),
            inventory: IndexInventory {
                shard_bytes,
                mapping_bytes,
                geometry_bytes,
                hash_state_bytes: HASH_STATE_BYTES,
                run_bytes,
                image_bytes,
                scratch_identities,
                scratch_bytes,
                participants,
                total,
            },
        })
    }

    /// `N[shard]` for a shard index below the count.
    fn limit(&self, shard: usize) -> usize {
        match self.shards {
            ShardLimits::Explicit(limits) => limits[shard],
            ShardLimits::Even { shards, total } => {
                total / shards + usize::from(shard < total % shards)
            }
        }
    }

    fn shard_geometry(
        &self,
        shard: ShardIndex,
        visible: usize,
        page_size: usize,
    ) -> Result<ShardGeometry, GeometryError> {
        if visible == 0 {
            return Ok(ShardGeometry::DISABLED);
        }
        let overflow_err = GeometryError::Overflow { shard };
        // The denominators are nonzero: validation proved `a > 0` and
        // `t > 0`, and a multiple of either that fits `usize` stays nonzero.
        let scaled = visible
            .checked_mul(self.load.denominator)
            .ok_or(overflow_err)?;
        let per_pair = self.load.numerator.checked_mul(PAIRS).ok_or(overflow_err)?;
        let base = scaled
            .div_ceil(per_pair)
            .max(1)
            .checked_next_power_of_two()
            .ok_or(overflow_err)?;
        let scaled = visible
            .checked_mul(self.overflow.numerator)
            .ok_or(overflow_err)?;
        let per_pair = self
            .overflow
            .denominator
            .checked_mul(PAIRS)
            .ok_or(overflow_err)?;
        let overflow = scaled.div_ceil(per_pair);
        let buckets = base.checked_add(overflow).ok_or(overflow_err)?;
        let physical = buckets.checked_mul(PAIRS).ok_or(overflow_err)?;
        let layout_err = GeometryError::LayoutOverflow { shard };
        let buckets = Layout::array::<Bucket>(buckets).map_err(|_| layout_err)?;
        let summaries = Layout::array::<AtomicU64>(base).map_err(|_| layout_err)?;
        let stack = Layout::array::<usize>(overflow).map_err(|_| layout_err)?;
        let (arrays, _) = buckets.extend(summaries).map_err(|_| layout_err)?;
        let (arrays, _) = arrays.extend(stack).map_err(|_| layout_err)?;
        let control = Layout::from_size_align(SHARD_CONTROL_BYTES, SHARD_CONTROL_ALIGN)
            .map_err(|_| layout_err)?;
        let (with_control, _) = arrays.extend(control).map_err(|_| layout_err)?;
        let extent = with_control
            .align_to(page_size)
            .map_err(|_| layout_err)?
            .pad_to_align()
            .size();
        Ok(ShardGeometry {
            visible,
            base,
            overflow,
            physical,
            extent,
        })
    }
}

impl ValidatedIndex {
    pub fn shard(&self, shard: ShardIndex) -> Option<&ShardGeometry> {
        self.shards.get(shard.0)
    }

    /// Every shard in index order, disabled ones included.
    pub fn shards(&self) -> &[ShardGeometry] {
        &self.shards
    }

    /// Shards routing may select, in index order.
    pub fn enabled(&self) -> &[EnabledShard] {
        &self.enabled
    }

    /// Overflow links a chain may follow, `D`.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Widest batch a registered reader may pass, `BatchMax`.
    pub fn batch_max(&self) -> usize {
        self.batch_max
    }

    /// Returns `F[s]` in shard order.
    pub fn fills(&self) -> &[usize] {
        &self.fills
    }

    /// The largest `F[s]`, the longest fill table one scan walks; zero when
    /// no shard has a table.
    pub fn fill_max(&self) -> usize {
        self.fill_max
    }

    /// Pairs a complete search examines at most: `14 * (1 + D)` along a
    /// chain. Equal to the scratch capacity in the inventory, and kept apart
    /// from it because the two are different obligations.
    pub fn chain_pairs(&self) -> usize {
        PAIRS * (1 + self.depth)
    }

    pub fn inventory(&self) -> IndexInventory {
        self.inventory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageConfig;

    const PAGE: usize = 4096;
    const READERS: usize = 4;

    /// One storage configuration of `slot_count` slots, sized so any test
    /// value fits.
    fn storage(slot_count: usize) -> StorageConfig {
        StorageConfig {
            page_size: PAGE,
            engine_budget: usize::MAX,
            body_cap: 3000,
            metadata_cap: Some(64),
            lease_limit: 8,
            object_rights: 8,
            reader_limit: READERS,
            volume: crate::storage::test_volume(2 * PAGE, slot_count),
        }
    }

    const NO_FILLS: [usize; 64] = [0; 64];

    fn config(
        shards: ShardLimits<'_>,
        load: (usize, usize),
        overflow: (usize, usize),
        depth: usize,
    ) -> IndexConfig<'_> {
        let count = match shards {
            ShardLimits::Explicit(limits) => limits.len(),
            ShardLimits::Even { shards, .. } => shards,
        };
        IndexConfig {
            shards,
            load: Ratio {
                numerator: load.0,
                denominator: load.1,
            },
            overflow: Ratio {
                numerator: overflow.0,
                denominator: overflow.1,
            },
            depth,
            batch_max: 4,
            fills: &NO_FILLS[..count.min(NO_FILLS.len())],
        }
    }

    fn validate(
        config: &IndexConfig<'_>,
        slot_count: usize,
    ) -> Result<ValidatedIndex, GeometryError> {
        // A volume holds at least one slot; a zero count asks for none visible.
        let storage = storage(slot_count.max(1)).validate().unwrap();
        config.validate(&storage)
    }

    /// `ceil(n / d)` spelled out, so the oracle shares no rounding helper
    /// with the code under test.
    fn ceil(n: usize, d: usize) -> usize {
        let whole = n / d;
        if whole * d == n { whole } else { whole + 1 }
    }

    /// The disabled shard, spelled out.
    const OFF: ShardGeometry = ShardGeometry {
        visible: 0,
        base: 0,
        overflow: 0,
        physical: 0,
        extent: 0,
    };

    /// Independent arithmetic for one shard: ceilings through [`ceil`],
    /// powers of two by doubling, the extent by hand from 128-byte buckets,
    /// 8-byte chain summaries, 8-byte stack entries and three 128-byte
    /// control blocks.
    fn expected(
        n: usize,
        (a, b): (usize, usize),
        (r, t): (usize, usize),
        page: usize,
    ) -> ShardGeometry {
        if n == 0 {
            return OFF;
        }
        let base = ceil(n * b, 14 * a).max(1);
        let mut pow = 1;
        while pow < base {
            pow *= 2;
        }
        let base = pow;
        let overflow = ceil(n * r, 14 * t);
        let bytes = (base + overflow) * 128 + base * 8 + overflow * 8;
        let bytes = ceil(bytes, 128) * 128 + 384;
        let extent = ceil(bytes, page) * page;
        ShardGeometry {
            visible: n,
            base,
            overflow,
            physical: 14 * (base + overflow),
            extent,
        }
    }

    #[test]
    fn tiny_domain_geometry_matches_independent_arithmetic() {
        let loads = [(1, 2), (2, 3), (9, 10), (1, 100)];
        let overflows = [(0, 1), (1, 4), (1, 1), (3, 2)];
        let limits: [usize; 7] = [0, 1, 2, 3, 5, 64, 1000];
        for &load in &loads {
            for &overflow in &overflows {
                for depth in [0, 1, 2] {
                    for &n in &limits {
                        let limits = [n];
                        let cfg = config(ShardLimits::Explicit(&limits), load, overflow, depth);
                        let validated = validate(&cfg, n).unwrap();
                        let shard = validated.shard(ShardIndex(0)).unwrap();
                        assert_eq!(
                            *shard,
                            expected(n, load, overflow, PAGE),
                            "{n} {load:?} {overflow:?}"
                        );
                        assert_eq!(validated.chain_pairs(), 14 * (1 + depth));
                        assert_eq!(validated.depth(), depth);
                        assert_eq!(validated.shards().len(), 1);
                        let inventory = validated.inventory();
                        assert_eq!(inventory.scratch_identities, 14 * (1 + depth));
                        assert_eq!(inventory.scratch_bytes, 8 * 14 * (1 + depth));
                        // The oracle's literal `14` is the bucket's pair count;
                        // a `PAIRS` change fails here before the oracle does.
                        assert_eq!(PAIRS, 14);
                        assert_eq!(validated.chain_pairs(), PAIRS * (1 + depth));
                        assert_eq!(inventory.scratch_identities, PAIRS * (1 + depth));
                        assert_eq!(shard.physical, PAIRS * (shard.base + shard.overflow));
                        assert_eq!(inventory.participants, READERS);
                        assert_eq!(inventory.hash_state_bytes, 32);
                        assert_eq!(inventory.shard_bytes, shard.extent);
                        let geometry_bytes = 40 + 8 + if n == 0 { 0 } else { 16 };
                        let run_bytes = if n == 0 { 0 } else { size_of::<BucketRun>() };
                        let image_bytes =
                            size_of::<Option<ShardImage>>() + size_of::<Option<FillImage>>();
                        assert_eq!(inventory.geometry_bytes, geometry_bytes);
                        assert_eq!(inventory.run_bytes, run_bytes);
                        assert_eq!(inventory.image_bytes, image_bytes);
                        let scratch = READERS * 8 * 14 * (1 + depth);
                        let mapping_bytes = ceil(shard.extent + scratch, PAGE) * PAGE;
                        assert_eq!(inventory.mapping_bytes, mapping_bytes);
                        assert_eq!(
                            inventory.total,
                            mapping_bytes + geometry_bytes + 32 + run_bytes + image_bytes
                        );
                        if n != 0 {
                            assert_eq!(
                                validated.enabled(),
                                &[EnabledShard {
                                    shard: ShardIndex(0),
                                    bucket_mask: shard.base - 1,
                                }]
                            );
                            assert!(shard.base.is_power_of_two());
                            assert_eq!(shard.bucket_mask(), Some(shard.base - 1));
                            // The base load never exceeds the target a/b.
                            assert!(n * load.1 <= 14 * shard.base * load.0);
                            assert_eq!(
                                shard.base_load(),
                                Some(Ratio {
                                    numerator: n,
                                    denominator: 14 * shard.base
                                })
                            );
                            assert_eq!(
                                shard.physical_load(),
                                Some(Ratio {
                                    numerator: n,
                                    denominator: shard.physical
                                })
                            );
                            assert!(shard.extent >= (shard.base + shard.overflow) * 128);
                            assert_eq!(shard.extent % PAGE, 0);
                        } else {
                            assert!(validated.enabled().is_empty());
                            assert_eq!(shard.bucket_mask(), None);
                            assert_eq!(shard.base_load(), None);
                            assert_eq!(shard.physical_load(), None);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn even_split_is_deterministic_and_disabled_shards_leave_routing() {
        let shards = |validated: &ValidatedIndex| -> Vec<usize> {
            validated.enabled().iter().map(|e| e.shard.0).collect()
        };
        // 7 over 3: 3, 2, 2.
        let cfg = config(
            ShardLimits::Even {
                shards: 3,
                total: 7,
            },
            (1, 2),
            (1, 4),
            1,
        );
        let validated = validate(&cfg, 7).unwrap();
        let visible: Vec<usize> = validated.shards().iter().map(|s| s.visible).collect();
        assert_eq!(visible, [3, 2, 2]);
        assert_eq!(shards(&validated), [0, 1, 2]);
        // 1 over 3: only the first shard is enabled.
        let cfg = config(
            ShardLimits::Even {
                shards: 3,
                total: 1,
            },
            (1, 2),
            (1, 4),
            1,
        );
        let validated = validate(&cfg, 4).unwrap();
        let visible: Vec<usize> = validated.shards().iter().map(|s| s.visible).collect();
        assert_eq!(visible, [1, 0, 0]);
        assert_eq!(shards(&validated), [0]);
        assert_eq!(validated.shards()[1], OFF);
        // Explicit with a disabled middle shard and an uneven pair, over a
        // volume whose slots equal the visible total.
        let limits = [5, 0, 2];
        let cfg = config(ShardLimits::Explicit(&limits), (1, 2), (1, 4), 0);
        let validated = validate(&cfg, 7).unwrap();
        assert_eq!(shards(&validated), [0, 2]);
        assert_eq!(validated.shard(ShardIndex(1)), Some(&OFF));
        assert_eq!(
            validated.inventory().shard_bytes,
            validated.shards()[0].extent + validated.shards()[2].extent
        );
        // Both shards empty: valid, nothing enabled, nothing charged for
        // arrays.
        let cfg = config(
            ShardLimits::Even {
                shards: 2,
                total: 0,
            },
            (1, 2),
            (1, 4),
            0,
        );
        let validated = validate(&cfg, 0).unwrap();
        assert!(validated.enabled().is_empty());
        assert_eq!(validated.inventory().shard_bytes, 0);
        assert_eq!(validated.shard(ShardIndex(2)), None);
    }

    #[test]
    fn every_refusal_is_distinct_and_leaves_the_input_untouched() {
        let limits = [4usize, 4];
        let good = config(ShardLimits::Explicit(&limits), (1, 2), (1, 4), 1);
        let copy = good;
        assert!(validate(&good, 8).is_ok());
        assert_eq!(good, copy);

        // The largest slot count storage validation admits, one below the
        // table index limit `2^31 - 1`.
        const MOST_SLOTS: usize = (1 << 31) - 2;
        let huge = [usize::MAX, 1];
        let one = [1usize];
        let wide = [1usize; 4];
        let cases: [(IndexConfig<'_>, usize, GeometryError); 14] = [
            (
                config(ShardLimits::Explicit(&[]), (1, 2), (1, 4), 1),
                8,
                GeometryError::NoShards,
            ),
            (
                config(
                    ShardLimits::Even {
                        shards: 0,
                        total: 4,
                    },
                    (1, 2),
                    (1, 4),
                    1,
                ),
                8,
                GeometryError::NoShards,
            ),
            // A shard count whose 40-byte geometry table does not fit
            // `isize::MAX`, refused before any per-shard work; only the
            // even split can name a count no slice could hold.
            (
                config(
                    ShardLimits::Even {
                        shards: 1 << 60,
                        total: 0,
                    },
                    (1, 2),
                    (1, 4),
                    1,
                ),
                8,
                GeometryError::ShardTableOverflow { shards: 1 << 60 },
            ),
            (
                config(ShardLimits::Explicit(&limits), (0, 2), (1, 4), 1),
                8,
                GeometryError::InvalidLoad(Ratio {
                    numerator: 0,
                    denominator: 2,
                }),
            ),
            (
                config(ShardLimits::Explicit(&limits), (2, 2), (1, 4), 1),
                8,
                GeometryError::InvalidLoad(Ratio {
                    numerator: 2,
                    denominator: 2,
                }),
            ),
            (
                config(ShardLimits::Explicit(&limits), (1, 2), (1, 0), 1),
                8,
                GeometryError::InvalidOverflow(Ratio {
                    numerator: 1,
                    denominator: 0,
                }),
            ),
            (
                config(ShardLimits::Explicit(&huge), (1, 2), (1, 4), 1),
                MOST_SLOTS,
                GeometryError::VisibleOverflow,
            ),
            (
                good,
                7,
                GeometryError::VisibleExceedsSlots {
                    visible: 8,
                    slots: 7,
                },
            ),
            (
                config(ShardLimits::Explicit(&one), (1, 2), (0, 1), usize::MAX),
                1,
                GeometryError::ScratchOverflow { depth: usize::MAX },
            ),
            (
                config(ShardLimits::Explicit(&one), (1, 2), (0, 1), 1 << 58),
                1,
                GeometryError::ScratchLayoutOverflow { depth: 1 << 58 },
            ),
            (
                // One key whose load ratio rounds the base array up to 2^61
                // buckets: their 14 pairs each do not fit `usize`.
                config(ShardLimits::Explicit(&one), (1, usize::MAX), (0, 1), 1),
                1,
                GeometryError::Overflow {
                    shard: ShardIndex(0),
                },
            ),
            // Arrays that fit `usize` but not `isize`: one key whose load
            // ratio asks for 2^56 buckets of 128 bytes.
            (
                config(ShardLimits::Explicit(&one), (1, 1 << 59), (0, 1), 1),
                1,
                GeometryError::LayoutOverflow {
                    shard: ShardIndex(0),
                },
            ),
            // One scratch fits `isize::MAX` (112 * 2^56 bytes), `R = 4` of
            // them do not fit `usize`.
            (
                config(ShardLimits::Explicit(&one), (1, 2), (0, 1), 1 << 56),
                1,
                GeometryError::InventoryOverflow,
            ),
            // Four shards of one key each, whose load ratio makes every base
            // array 2^55 buckets of 128 bytes: each extent fits `isize::MAX`,
            // their sum does not fit `usize`.
            (
                config(ShardLimits::Explicit(&wide), (1, 7 << 56), (0, 1), 1),
                4,
                GeometryError::InventoryOverflow,
            ),
        ];
        for (cfg, slots, expected) in cases {
            let before = cfg;
            assert_eq!(validate(&cfg, slots).err(), Some(expected), "{cfg:?}");
            assert_eq!(cfg, before);
        }
        // The same shard-zero product refusal and a scratch refusal are
        // distinct values, so a caller can tell which bound failed.
        assert_ne!(
            GeometryError::Overflow {
                shard: ShardIndex(0)
            },
            GeometryError::ScratchOverflow { depth: 0 }
        );
    }

    /// The fill table sizes are shape-checked with the shard limits: one per
    /// configured shard, zero on a disabled shard, and two record arrays that
    /// fit `isize::MAX`; a valid shape is carried through unchanged, with its
    /// largest table.
    #[test]
    fn fill_sizes_are_shape_checked_and_carried_through() {
        let limits = [4usize, 0, 4];
        let good = IndexConfig {
            fills: &[2, 0, 7],
            ..config(ShardLimits::Explicit(&limits), (1, 2), (1, 4), 1)
        };
        let validated = validate(&good, 8).unwrap();
        assert_eq!(validated.fills(), [2, 0, 7]);
        assert_eq!(validated.fill_max(), 7);
        assert_eq!(
            validated.inventory().geometry_bytes,
            3 * 40 + 3 * 8 + 2 * 16
        );
        let cases: [(&[usize], GeometryError); 4] = [
            (
                &[2, 0],
                GeometryError::FillShape {
                    shards: 3,
                    fills: 2,
                },
            ),
            (
                &[2, 0, 7, 1],
                GeometryError::FillShape {
                    shards: 3,
                    fills: 4,
                },
            ),
            (
                &[2, 1, 7],
                GeometryError::FillOnDisabledShard {
                    shard: ShardIndex(1),
                },
            ),
            (
                &[2, 0, usize::MAX / 16],
                GeometryError::FillLayoutOverflow {
                    shard: ShardIndex(2),
                },
            ),
        ];
        for (fills, expected) in cases {
            let cfg = IndexConfig { fills, ..good };
            let before = cfg;
            assert_eq!(validate(&cfg, 8).err(), Some(expected), "{fills:?}");
            assert_eq!(cfg, before);
        }
        // A shape refusal precedes every per-shard check, and a zero
        // table is valid on every enabled shard.
        let even = IndexConfig {
            fills: &[0, 0],
            ..config(
                ShardLimits::Even {
                    shards: 2,
                    total: 8,
                },
                (1, 2),
                (1, 4),
                1,
            )
        };
        let even = validate(&even, 8).unwrap();
        assert_eq!(even.fills(), [0, 0]);
        assert_eq!(even.fill_max(), 0);
    }
}
