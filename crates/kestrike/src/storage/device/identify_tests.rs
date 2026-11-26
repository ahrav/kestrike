//! Identify capture, decoding and `completion-without-volatile-cache` eligibility over
//! native fixtures. Distinct fixture values expose a read from the wrong
//! field.

use spdk_sys as sys;

use super::identify::{
    AttachedIdentity, IDENTIFY_LEN, IdentifyFacts, IdentifyMalformed, IdentifyRaw, IdentifyRecord,
    IdentifySnapshot, TransferLimits,
};
use super::profile::{ProfileRefusal, completion_is_durable};

pub(crate) const SERIAL: &str = "vol0123456789abcdef0";

fn padded<const N: usize>(text: &str) -> [i8; N] {
    let mut field = [b' ' as i8; N];
    for (slot, byte) in field.iter_mut().zip(text.bytes()) {
        *slot = byte as i8;
    }
    field
}

pub(crate) fn controller(serial: &str) -> Box<sys::spdk_nvme_ctrlr_data> {
    let mut data = Box::new(sys::spdk_nvme_ctrlr_data::default());
    data.sn = padded(serial);
    data.mn = padded("Amazon Elastic Block Store");
    data.fr = padded::<8>("2.0").map(|byte| byte as u8);
    data.ver.raw = (1 << 16) | (4 << 8);
    data.mdts = 6;
    data.awun = 0;
    data.awupf = 7;
    data.acwu = 2;
    let mut oncs = data.oncs;
    oncs.set_write_zeroes(1);
    oncs.set_dsm(1);
    oncs.set_copy(1);
    data.oncs = oncs;
    data
}

/// A namespace of `sectors` blocks whose active format is index 1 with
/// `2^lbads`-byte blocks. When `lbads != 12`, the decoded block size
/// distinguishes format 1 from format 0.
pub(crate) fn namespace(sectors: u64, lbads: u32) -> Box<sys::spdk_nvme_ns_data> {
    let mut data = Box::new(sys::spdk_nvme_ns_data::default());
    data.nsze = sectors;
    data.ncap = sectors;
    data.nlbaf = 1;
    data.flbas.set_format(1);
    data.lbaf[0].set_lbads(12);
    data.lbaf[1].set_lbads(lbads);
    data.nsfeat.set_ns_atomic_write_unit(1);
    data.nawun = 3;
    data.nawupf = 4;
    data.nacwu = 1;
    data.nabsn = 15;
    data.nabo = 5;
    data.nabspf = 0;
    data.noiob = 256;
    data
}

/// # Safety
///
/// `T` is plain data with every byte initialized.
unsafe fn bytes<T>(value: &T) -> [u8; IDENTIFY_LEN] {
    const { assert!(size_of::<T>() == IDENTIFY_LEN) };
    // SAFETY: `T` is `IDENTIFY_LEN` bytes, every one initialized by the caller's contract.
    unsafe {
        std::ptr::from_ref(value)
            .cast::<[u8; IDENTIFY_LEN]>()
            .read()
    }
}

fn captured(c: &sys::spdk_nvme_ctrlr_data, n: &sys::spdk_nvme_ns_data) -> IdentifyRaw {
    // SAFETY: both references are readable structures.
    unsafe { IdentifyRaw::capture(c, n, 1) }.unwrap()
}

fn attached() -> AttachedIdentity {
    AttachedIdentity {
        serial: SERIAL.to_owned(),
        nsid: 1,
        sector_size: 512,
        capacity: 1 << 30,
    }
}

#[test]
fn a_capture_owns_both_structures_after_the_native_fixture_is_overwritten_and_dropped() {
    let (mut c, mut n) = (controller(SERIAL), namespace(1 << 21, 9));
    // SAFETY: both Identify bindings are plain data whose fields tile their bytes.
    let (expected_c, expected_n) = unsafe { (bytes(&*c), bytes(&*n)) };
    let raw = captured(&c, &n);
    *c = sys::spdk_nvme_ctrlr_data::default();
    *n = sys::spdk_nvme_ns_data::default();
    drop((c, n));
    let transfer = TransferLimits {
        namespace_max: 128 << 10,
        boundary: 0,
        command: 128 << 10,
    };
    let snapshot = IdentifySnapshot::new(raw.clone(), transfer);
    assert_eq!(snapshot.raw().controller(), &expected_c);
    assert_eq!(snapshot.raw().namespace(), &expected_n);
    assert_eq!(snapshot.raw(), &raw);
    assert_eq!(
        snapshot.decoded().cloned(),
        IdentifyFacts::decode(snapshot.raw())
    );
    assert_eq!(snapshot.transfer(), transfer);
    let facts = snapshot.decoded().unwrap();
    assert_eq!(facts.serial, SERIAL);
    assert_eq!(facts.model, "Amazon Elastic Block Store");
    assert_eq!(facts.firmware, "2.0");
    assert_eq!(
        (
            facts.version.major,
            facts.version.minor,
            facts.version.tertiary
        ),
        (1, 4, 0)
    );
    assert!(!facts.volatile_write_cache.present);
    assert_eq!(facts.oncs, (1 << 2) | (1 << 3) | (1 << 8));
    assert_eq!(
        (facts.mdts, facts.awun, facts.awupf, facts.acwu),
        (6, 0, 7, 2)
    );
    assert_eq!(
        (
            facts.nsid,
            facts.sectors,
            facts.lba_format,
            facts.sector_size
        ),
        (1, 1 << 21, 1, 512)
    );
    let atomics = facts.atomics;
    assert!(atomics.applies);
    assert_eq!(
        (
            atomics.nawun,
            atomics.nawupf,
            atomics.nacwu,
            atomics.nabsn,
            atomics.nabo,
            atomics.nabspf,
            atomics.noiob
        ),
        (3, 4, 1, 15, 5, 0, 256)
    );
}

#[test]
fn a_null_namespace_structure_captures_nothing() {
    let c = controller(SERIAL);
    // SAFETY: a null namespace pointer is never read.
    assert!(unsafe { IdentifyRaw::capture(&c, std::ptr::null(), 1) }.is_none());
}

#[test]
fn decode_reads_each_cache_and_applicability_bit_on_its_own() {
    let mut c = controller(SERIAL);
    let mut vwc = c.vwc;
    vwc.set_flush_broadcast(3);
    c.vwc = vwc;
    let mut n = namespace(1 << 21, 9);
    n.nsfeat.set_ns_atomic_write_unit(0);
    n.nsfeat.set_thin_prov(1);
    let facts = IdentifyFacts::decode(&captured(&c, &n)).unwrap();
    assert_eq!(
        (
            facts.volatile_write_cache.present,
            facts.volatile_write_cache.flush_broadcast
        ),
        (false, 3)
    );
    assert!(!facts.atomics.applies);
    let raw = captured(&c, &n);
    assert_eq!(completion_is_durable(raw.record(), &attached()), Ok(()));
    vwc.set_present(1);
    c.vwc = vwc;
    let facts = IdentifyFacts::decode(&captured(&c, &n)).unwrap();
    assert_eq!(
        (
            facts.volatile_write_cache.present,
            facts.volatile_write_cache.flush_broadcast
        ),
        (true, 3)
    );
}

#[test]
fn decode_reads_the_high_format_index_bits_only_past_sixteen_formats() {
    let c = controller(SERIAL);
    let mut n = namespace(1 << 21, 9);
    n.nlbaf = 20;
    n.flbas.set_format(1);
    n.flbas.set_msb_format(1);
    n.lbaf[17].set_lbads(12);
    n.lbaf[17].set_ms(8);
    let facts = IdentifyFacts::decode(&captured(&c, &n)).unwrap();
    assert_eq!(
        (facts.lba_format, facts.sector_size, facts.metadata_size),
        (17, 4096, 8)
    );
    // NLBAF is zero-based: 16 reports seventeen formats, so index 16 needs the
    // high bits.
    n.nlbaf = 16;
    n.flbas.set_format(0);
    n.lbaf[16].set_lbads(9);
    n.lbaf[16].set_ms(8);
    let facts = IdentifyFacts::decode(&captured(&c, &n)).unwrap();
    assert_eq!(
        (facts.lba_format, facts.sector_size, facts.metadata_size),
        (16, 512, 8)
    );
    n.flbas.set_format(1);
    assert_eq!(
        IdentifyFacts::decode(&captured(&c, &n)),
        Err(IdentifyMalformed::LbaFormat {
            index: 17,
            last: 16
        })
    );
    n.nlbaf = 15;
    let facts = IdentifyFacts::decode(&captured(&c, &n)).unwrap();
    assert_eq!((facts.lba_format, facts.sector_size), (1, 512));
}

#[test]
fn decode_refuses_text_formats_and_block_sizes_outside_the_specification() {
    let c = controller(SERIAL);
    let mut n = namespace(1 << 21, 9);
    n.flbas.set_format(2);
    assert_eq!(
        IdentifyFacts::decode(&captured(&c, &n)),
        Err(IdentifyMalformed::LbaFormat { index: 2, last: 1 })
    );
    let n = namespace(1 << 21, 8);
    assert_eq!(
        IdentifyFacts::decode(&captured(&c, &n)),
        Err(IdentifyMalformed::SectorSize(8))
    );
    let mut c = controller(SERIAL);
    c.sn[3] = -1;
    let n = namespace(1 << 21, 9);
    assert_eq!(
        IdentifyFacts::decode(&captured(&c, &n)),
        Err(IdentifyMalformed::Text)
    );
}

#[test]
fn the_profile_admits_only_a_whole_matching_record_without_a_volatile_write_cache() {
    let n = namespace(1 << 21, 9);
    let raw = captured(&controller(SERIAL), &n);
    assert_eq!(completion_is_durable(raw.record(), &attached()), Ok(()));
    let mut cached = controller(SERIAL);
    let mut vwc = cached.vwc;
    vwc.set_present(1);
    cached.vwc = vwc;
    assert_eq!(
        completion_is_durable(captured(&cached, &n).record(), &attached()),
        Err(ProfileRefusal::VolatileWriteCache)
    );
    let whole = raw.record();
    for incomplete in [
        IdentifyRecord {
            controller: None,
            ..whole
        },
        IdentifyRecord {
            namespace: None,
            ..whole
        },
        IdentifyRecord {
            namespace: Some(&raw.namespace()[..IDENTIFY_LEN - 1]),
            ..whole
        },
    ] {
        assert_eq!(
            completion_is_durable(incomplete, &attached()),
            Err(ProfileRefusal::Incomplete)
        );
    }
    let malformed = captured(&controller(SERIAL), &namespace(1 << 21, 40));
    assert_eq!(
        completion_is_durable(malformed.record(), &attached()),
        Err(ProfileRefusal::Malformed(IdentifyMalformed::SectorSize(40)))
    );
    let stale = [
        AttachedIdentity {
            serial: "vol0fedcba9876543210".to_owned(),
            ..attached()
        },
        AttachedIdentity {
            nsid: 2,
            ..attached()
        },
        AttachedIdentity {
            sector_size: 4096,
            ..attached()
        },
        AttachedIdentity {
            capacity: 2 << 30,
            ..attached()
        },
    ];
    let overflowing = captured(&controller(SERIAL), &namespace((1 << 55) + (1 << 21), 9));
    assert_eq!(
        completion_is_durable(overflowing.record(), &attached()),
        Err(ProfileRefusal::Mismatch)
    );
    assert_eq!(
        completion_is_durable(captured(&cached, &n).record(), &stale[1]),
        Err(ProfileRefusal::Mismatch),
        "a stale identity refuses before the volatile write cache"
    );
    for other in &stale {
        assert_eq!(
            completion_is_durable(raw.record(), other),
            Err(ProfileRefusal::Mismatch),
            "{other:?}"
        );
    }
}
