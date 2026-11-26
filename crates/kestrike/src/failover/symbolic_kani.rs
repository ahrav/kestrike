//! Record values for the failover harnesses: each field but a volume name ranges over every value its type admits,
//! independently of the other fields. The harnesses built on them therefore also cover records the decoders refuse,
//! such as a spare equal to the active volume, a standby equal to the owner, `E` above `ATTEMPTS_MAX` or a nonzero
//! cut without a checkpoint.

#[cfg(kani)]
pub(super) mod values {
    use core::num::{NonZeroU16, NonZeroU32};

    use super::super::records::{
        Ancestry, Host, MAX_CHAIN, NamedCheckpoint, Namespace, ShardRecord, Suffix, VolumeId,
    };
    use super::super::retire::Target;
    use crate::net::ownership::{Shard, ShardGeneration};

    pub(crate) fn host() -> Host {
        let host = Host::new(kani::any());
        kani::assume(host.is_some());
        host.unwrap()
    }

    /// One of three distinct volume names. The decisions these harnesses check use a volume name only through equality
    /// with another, and no harness's decisions tell more than three classes of equal volumes apart, so three names
    /// realize every pattern of equal and distinct volumes the decisions can see. The pending-count proof draws five
    /// volumes and compares each census shard's active volume with the two reported entries' volumes alone.
    pub(crate) fn volume() -> VolumeId {
        let name = match kani::any::<u8>() % 3 {
            0 => "vol-1",
            1 => "vol-2",
            _ => "vol-3",
        };
        VolumeId::new(name).unwrap()
    }

    /// A namespace in the range [`Namespace::new`] admits.
    pub(crate) fn namespace() -> Namespace {
        let namespace = Namespace::new(kani::any());
        kani::assume(namespace.is_some());
        namespace.unwrap()
    }

    pub(crate) fn shard() -> Shard {
        let shard = Shard::new(kani::any());
        kani::assume(shard.is_some());
        shard.unwrap()
    }

    /// A generation in `1..=2^32 - 1`, the range [`ShardGeneration::new`] admits.
    pub(crate) fn generation() -> ShardGeneration {
        let generation = ShardGeneration::new(kani::any());
        kani::assume(generation.is_some());
        generation.unwrap()
    }

    /// A tenure `(g, owner, E)` with `E` any `u32`.
    pub(crate) fn target() -> Target {
        Target {
            generation: generation(),
            owner: host(),
            attempts: kani::any(),
        }
    }

    fn suffix() -> Suffix {
        Suffix {
            session: kani::any(),
            start: kani::any(),
            certified: kani::any(),
            end: kani::any(),
        }
    }

    /// A shard record whose ancestry holds zero to [`MAX_CHAIN`] suffixes and whose spare, checkpoint and standby are
    /// each present or absent.
    pub(crate) fn shard_record() -> ShardRecord {
        let suffixes: [Suffix; MAX_CHAIN] = core::array::from_fn(|_| suffix());
        let len: usize = kani::any();
        kani::assume(len <= MAX_CHAIN);
        let tenure = target();
        ShardRecord {
            shard: shard(),
            generation: tenure.generation,
            active: volume(),
            owner: tenure.owner,
            attempts: tenure.attempts,
            spare: kani::any::<bool>().then(|| (volume(), host())),
            checkpoint: kani::any::<bool>().then(|| NamedCheckpoint {
                slot: kani::any(),
                session: kani::any(),
                capture: kani::any(),
                units: kani::any(),
            }),
            cut: kani::any(),
            pages: kani::any::<NonZeroU16>(),
            page_cap: kani::any::<NonZeroU32>(),
            namespace: namespace(),
            ancestry: Ancestry::new(&suffixes[..len]).unwrap(),
            standby: kani::any::<bool>().then(host),
        }
    }
}
