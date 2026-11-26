//! Validation of a buffer arena's pool sizes and carving, with no OS call
//! and no allocation.
//!
//! An arena holds any non-empty set of pool kinds. Every buffer length is a
//! power of two of at least [`IO_UNIT`] that divides the hugepage size, and
//! every pool's span starts at a multiple of its buffer length, so no buffer
//! crosses a backing page and separately backed hugepages never join inside
//! one buffer. Pools are carved in [`PoolKind::ALL`] order; the padding a
//! pool's alignment needs and the tail after the last pool stay mapped and
//! charged.

use super::super::config::is_page_multiple;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;

pub use super::super::layout::{IO_UNIT, SECTOR};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolKind {
    /// Buffers that receive device reads for responses.
    ReadResponse,
    /// Buffers that hold received bytes until a device write takes them.
    ReceiveWrite,
    /// Buffers for background device work.
    Maintenance,
    /// Packet buffers a network device receives frames into.
    PacketReceive,
    /// Packet buffers holding transmit headers.
    PacketHeader,
    /// Buffers reserved for reservation commands, separate from metadata work.
    Reservation,
}

impl PoolKind {
    pub const ALL: [Self; 6] = [
        Self::ReadResponse,
        Self::ReceiveWrite,
        Self::Maintenance,
        Self::PacketReceive,
        Self::PacketHeader,
        Self::Reservation,
    ];
    /// The kinds a storage volume needs.
    pub const STORAGE: [Self; 3] = [Self::ReadResponse, Self::ReceiveWrite, Self::Maintenance];
    /// The kinds a network endpoint needs.
    pub const PACKET: [Self; 2] = [Self::PacketReceive, Self::PacketHeader];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::ReadResponse => 0,
            Self::ReceiveWrite => 1,
            Self::Maintenance => 2,
            Self::PacketReceive => 3,
            Self::PacketHeader => 4,
            Self::Reservation => 5,
        }
    }
}

/// One pool's size: `count` buffers of `buffer_len` bytes each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSpec {
    pub kind: PoolKind,
    pub count: u32,
    pub buffer_len: u32,
}

/// Caller-chosen arena configuration, checked by [`validate`](Self::validate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferConfig<'a> {
    /// Page size backing the whole arena.
    pub hugepage: HugepageSize,
    /// Nodes the backing is bound to before its first touch.
    pub nodes: NodeMask,
    /// At most one entry per [`PoolKind`], in any order; at least one.
    pub pools: &'a [PoolSpec],
}

/// The first fault [`BufferConfig::validate`] finds, in the check order its `# Errors` section lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferConfigError {
    EmptyNodeMask,
    /// No pool is configured.
    NoPools,
    DuplicateKind(PoolKind),
    ZeroCount(PoolKind),
    ZeroBufferLen(PoolKind),
    /// `buffer_len` is not a power of two of at least [`IO_UNIT`] that divides the hugepage size.
    MisalignedBufferLen {
        kind: PoolKind,
        buffer_len: u32,
    },
    /// Summing the pools, their alignment padding, or rounding up to the
    /// hugepage size overflows `usize`.
    BackingOverflow,
    /// The backing exceeds `isize::MAX`, the largest extent a pointer offset within one mapping can span.
    BackingTooLarge {
        backing_len: usize,
    },
}

/// A configuration that passed [`BufferConfig::validate`]. It owns a copy of
/// every pool, indexed by kind; an absent kind has a count of zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedBufferConfig {
    hugepage: HugepageSize,
    nodes: NodeMask,
    pools: [PoolSpec; PoolKind::ALL.len()],
    /// Each pool's span start from the backing base.
    starts: [usize; PoolKind::ALL.len()],
    payload_len: usize,
    backing_len: usize,
}

impl BufferConfig<'_> {
    /// Checks the configuration and computes the carving and backing extent.
    ///
    /// # Errors
    ///
    /// In this order, stopping at the first failure:
    ///
    /// - `EmptyNodeMask` if `nodes` names no node. Whether each node exists,
    ///   has memory and is allowed is checked against the kernel's topology
    ///   at arena initialization.
    /// - `NoPools` if `pools` is empty.
    /// - Per entry of `pools`, in slice order: `DuplicateKind` for a kind
    ///   already seen, then `ZeroCount`, `ZeroBufferLen`, and
    ///   `MisalignedBufferLen`.
    /// - `BackingOverflow` if the pools with their padding, or their round-up
    ///   to the hugepage size, overflows `usize`.
    /// - `BackingTooLarge` if the backing exceeds `isize::MAX`.
    pub fn validate(&self) -> Result<ValidatedBufferConfig, BufferConfigError> {
        if self.nodes.is_empty() {
            return Err(BufferConfigError::EmptyNodeMask);
        }
        if self.pools.is_empty() {
            return Err(BufferConfigError::NoPools);
        }
        let hugepage = self.hugepage.bytes();
        let mut pools = PoolKind::ALL.map(|kind| PoolSpec {
            kind,
            count: 0,
            buffer_len: 0,
        });
        for spec in self.pools {
            let kind = spec.kind;
            if pools[kind.index()].count != 0 {
                return Err(BufferConfigError::DuplicateKind(kind));
            }
            if spec.count == 0 {
                return Err(BufferConfigError::ZeroCount(kind));
            }
            if spec.buffer_len == 0 {
                return Err(BufferConfigError::ZeroBufferLen(kind));
            }
            let len = spec.buffer_len as usize;
            if !len.is_power_of_two() || len < IO_UNIT || !hugepage.is_multiple_of(len) {
                return Err(BufferConfigError::MisalignedBufferLen {
                    kind,
                    buffer_len: spec.buffer_len,
                });
            }
            pools[kind.index()] = *spec;
        }
        let mut starts = [0; PoolKind::ALL.len()];
        let mut end = 0usize;
        for spec in &pools {
            if spec.count == 0 {
                continue;
            }
            let len = spec.buffer_len as usize;
            let start = end
                .checked_next_multiple_of(len)
                .ok_or(BufferConfigError::BackingOverflow)?;
            starts[spec.kind.index()] = start;
            end = (spec.count as usize)
                .checked_mul(len)
                .and_then(|span| start.checked_add(span))
                .ok_or(BufferConfigError::BackingOverflow)?;
        }
        let backing_len = end
            .checked_next_multiple_of(hugepage)
            .ok_or(BufferConfigError::BackingOverflow)?;
        if !is_page_multiple(backing_len, hugepage) {
            return Err(BufferConfigError::BackingTooLarge { backing_len });
        }
        Ok(ValidatedBufferConfig {
            hugepage: self.hugepage,
            nodes: self.nodes,
            pools,
            starts,
            payload_len: end,
            backing_len,
        })
    }
}

impl ValidatedBufferConfig {
    pub fn hugepage(&self) -> HugepageSize {
        self.hugepage
    }

    pub fn nodes(&self) -> &NodeMask {
        &self.nodes
    }

    /// The pool of `kind`; its count is zero when the arena holds no such pool.
    pub fn pool(&self, kind: PoolKind) -> PoolSpec {
        self.pools[kind.index()]
    }

    /// Bytes from the backing base to the start of `kind`'s span, a multiple of its buffer length.
    pub(crate) fn start(&self, kind: PoolKind) -> usize {
        self.starts[kind.index()]
    }

    /// Bytes of the hugepage backing, padding and tail included: the arena
    /// maps and charges exactly this. Positive, because at least one pool
    /// holds at least one buffer of at least one unit.
    pub fn backing_len(&self) -> usize {
        self.backing_len
    }

    /// Bytes [`BufferArena::initialize`](super::BufferArena::initialize)
    /// charges.
    pub fn charge(&self) -> usize {
        self.charges().into_iter().fold(0, usize::saturating_add)
    }

    pub(crate) fn charges(&self) -> [usize; 2] {
        [self.backing_len, super::pool::Pools::metadata_bytes(self)]
    }

    /// Bytes after the last pool, shorter than one hugepage.
    pub fn tail_len(&self) -> usize {
        self.backing_len - self.payload_len
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::os::HugepageSize;
    use super::super::super::placement::NodeMask;
    use super::{BufferConfig, BufferConfigError, PoolKind, PoolSpec};

    const MIB: usize = 1 << 20;
    const GIB: u32 = 1 << 30;

    fn spec(kind: PoolKind, count: u32, buffer_len: u32) -> PoolSpec {
        PoolSpec {
            kind,
            count,
            buffer_len,
        }
    }

    fn three() -> [PoolSpec; 3] {
        [
            spec(PoolKind::Maintenance, 2, 8192),
            spec(PoolKind::ReadResponse, 64, 16384),
            spec(PoolKind::ReceiveWrite, 32, 4096),
        ]
    }

    fn config(hugepage: HugepageSize, pools: &[PoolSpec]) -> BufferConfig<'_> {
        BufferConfig {
            hugepage,
            nodes: NodeMask::from_nodes(&[0]).unwrap(),
            pools,
        }
    }

    #[test]
    fn a_valid_configuration_reports_backing_and_tail_for_both_page_sizes() {
        let pools = three();
        let payload = 2 * 8192 + 64 * 16384 + 32 * 4096;
        for (hugepage, backing) in [
            (HugepageSize::TwoMiB, 2 * MIB),
            (HugepageSize::OneGiB, 1024 * MIB),
        ] {
            let validated = config(hugepage, &pools).validate().unwrap();
            assert_eq!(validated.hugepage(), hugepage);
            assert_eq!(validated.nodes(), &NodeMask::from_nodes(&[0]).unwrap());
            assert_eq!(validated.backing_len(), backing);
            assert_eq!(validated.tail_len(), backing - payload);
            assert_eq!(validated.pool(PoolKind::ReadResponse), pools[1]);
            assert_eq!(validated.pool(PoolKind::ReceiveWrite), pools[2]);
            assert_eq!(validated.pool(PoolKind::Maintenance), pools[0]);
            assert!(
                PoolKind::STORAGE
                    .iter()
                    .all(|kind| validated.pool(*kind).count > 0)
            );
            assert_eq!(validated.pool(PoolKind::PacketReceive).count, 0);
            assert_eq!(validated.pool(PoolKind::PacketHeader).count, 0);
        }
    }

    /// Each span starts at a multiple of its buffer length; the padding
    /// before it is charged as payload, and a packet-only arena is valid.
    #[test]
    fn spans_start_at_their_stride_and_padding_is_charged() {
        let pools = [
            spec(PoolKind::ReadResponse, 3, 4096),
            spec(PoolKind::PacketReceive, 2, 16384),
            spec(PoolKind::PacketHeader, 4, 4096),
        ];
        let validated = config(HugepageSize::TwoMiB, &pools).validate().unwrap();
        assert_eq!(validated.start(PoolKind::ReadResponse), 0);
        assert_eq!(
            validated.start(PoolKind::PacketReceive),
            16384,
            "12 KiB of padding before the 16 KiB stride"
        );
        assert_eq!(validated.start(PoolKind::PacketHeader), 16384 + 2 * 16384);
        assert_eq!(validated.tail_len(), 2 * MIB - (3 * 16384 + 4 * 4096));
        let packets = config(HugepageSize::TwoMiB, &pools[1..])
            .validate()
            .unwrap();
        assert!(
            PoolKind::PACKET
                .iter()
                .all(|kind| packets.pool(*kind).count > 0)
        );
        assert_eq!(packets.pool(PoolKind::ReadResponse).count, 0);
        assert_eq!(packets.start(PoolKind::PacketReceive), 0);
    }

    /// Over seeded configurations of every kind subset and stride for 2 MiB and 1 GiB pages, every buffer lies inside one backing page and its pool's span, and no two spans overlap. A forged per-page device address table maps each page far from its neighbours, so a buffer is device-contiguous exactly when its first and last byte translate one buffer length apart minus one.
    #[test]
    fn no_buffer_crosses_a_backing_page() {
        let mut rng = crate::storage::seeded::SplitMix64::new(0xC0FE);
        for round in 0..400 {
            let hugepage = if round % 2 == 0 {
                HugepageSize::TwoMiB
            } else {
                HugepageSize::OneGiB
            };
            let page = hugepage.bytes();
            let mut pools = Vec::new();
            for kind in PoolKind::ALL {
                if rng.below(3) == 0 {
                    continue;
                }
                // Strides from 4 KiB up to the page size or 4 MiB, whichever is smaller.
                let max_shift = page.trailing_zeros() - 12;
                let shift = rng.below(u64::from(max_shift.min(10)) + 1) as u32;
                let stride = 4096u32 << shift;
                let count =
                    1 + rng.below((4 * page as u64 / u64::from(stride)).clamp(1, 64)) as u32;
                pools.push(spec(kind, count, stride));
            }
            if pools.is_empty() {
                continue;
            }
            let validated = config(hugepage, &pools).validate().unwrap();
            let pages = validated.backing_len() / page;
            // Page `p` translates to a device address in reverse order with a gap, so adjacent pages are never adjacent on the device.
            let device = |offset: usize| {
                let p = offset / page;
                ((pages - p) * 3 * page + offset % page) as u64
            };
            let mut spans = Vec::new();
            for spec in &pools {
                let start = validated.start(spec.kind);
                let len = spec.buffer_len as usize;
                assert!(start.is_multiple_of(len), "{pools:?}");
                for at in 0..spec.count as usize {
                    let first = start + at * len;
                    let last = first + len - 1;
                    assert_eq!(
                        first / page,
                        last / page,
                        "{spec:?} buffer {at} crosses a page"
                    );
                    assert_eq!(
                        device(last) - device(first),
                        len as u64 - 1,
                        "{spec:?} buffer {at}"
                    );
                }
                spans.push(start..start + spec.count as usize * len);
            }
            spans.sort_by_key(|span| span.start);
            assert!(
                spans.windows(2).all(|pair| pair[0].end <= pair[1].start),
                "{pools:?}"
            );
            assert!(spans.last().unwrap().end <= validated.backing_len());
        }
    }

    #[test]
    fn a_payload_of_whole_hugepages_has_no_tail() {
        let pools = [
            spec(PoolKind::ReadResponse, 512, 4096),
            spec(PoolKind::ReceiveWrite, 1, 2 * MIB as u32),
            spec(PoolKind::Maintenance, 256, 8192),
        ];
        let validated = config(HugepageSize::TwoMiB, &pools).validate().unwrap();
        assert_eq!(validated.backing_len(), 6 * MIB);
        assert_eq!(validated.tail_len(), 0);
    }

    #[test]
    fn each_invalid_input_is_refused_with_its_own_error() {
        let ok = three();
        let with = |index: usize, replacement: PoolSpec| {
            let mut pools = ok;
            pools[index] = replacement;
            pools
        };
        let huge = |kind| spec(kind, u32::MAX, GIB);
        let misaligned = |len| BufferConfigError::MisalignedBufferLen {
            kind: PoolKind::ReceiveWrite,
            buffer_len: len,
        };
        let cases: [(&[PoolSpec], HugepageSize, BufferConfigError); 9] = [
            (&[], HugepageSize::TwoMiB, BufferConfigError::NoPools),
            (
                &with(2, spec(PoolKind::Maintenance, 1, 4096)),
                HugepageSize::TwoMiB,
                BufferConfigError::DuplicateKind(PoolKind::Maintenance),
            ),
            (
                &with(1, spec(PoolKind::ReadResponse, 0, 4096)),
                HugepageSize::TwoMiB,
                BufferConfigError::ZeroCount(PoolKind::ReadResponse),
            ),
            (
                &with(2, spec(PoolKind::ReceiveWrite, 1, 0)),
                HugepageSize::TwoMiB,
                BufferConfigError::ZeroBufferLen(PoolKind::ReceiveWrite),
            ),
            (
                &with(2, spec(PoolKind::ReceiveWrite, 1, 4097)),
                HugepageSize::TwoMiB,
                misaligned(4097),
            ),
            (
                &with(2, spec(PoolKind::ReceiveWrite, 1, 2048)),
                HugepageSize::TwoMiB,
                misaligned(2048),
            ),
            (
                &with(2, spec(PoolKind::ReceiveWrite, 1, 12288)),
                HugepageSize::TwoMiB,
                misaligned(12288),
            ),
            (
                &with(2, spec(PoolKind::ReceiveWrite, 1, 4 << 20)),
                HugepageSize::TwoMiB,
                misaligned(4 << 20),
            ),
            (
                &PoolKind::ALL.map(huge),
                HugepageSize::OneGiB,
                BufferConfigError::BackingOverflow,
            ),
        ];
        for (pools, hugepage, expected) in cases {
            assert_eq!(
                config(hugepage, pools).validate(),
                Err(expected),
                "{pools:?}"
            );
        }
        let three = PoolKind::STORAGE.map(huge);
        assert_eq!(
            config(HugepageSize::OneGiB, &three).validate(),
            Err(BufferConfigError::BackingTooLarge {
                backing_len: 3 * u32::MAX as usize * GIB as usize
            })
        );
        let empty = BufferConfig {
            nodes: NodeMask::default(),
            ..config(HugepageSize::TwoMiB, &ok)
        };
        assert_eq!(empty.validate(), Err(BufferConfigError::EmptyNodeMask));
    }
}
