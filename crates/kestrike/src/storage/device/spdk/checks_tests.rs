//! The driver's rules over native results.

use super::super::disk::{QuiesceStatus, RefusalReason};
use super::certify::disable_proven;
use super::checks::{disconnect_outcome, identity_matches, refusal_for};
use super::disk::SpdkConfig;

fn field<const N: usize>(text: &str, pad: u8) -> [i8; N] {
    let mut out = [pad as i8; N];
    for (slot, byte) in out.iter_mut().zip(text.bytes()) {
        *slot = byte as i8;
    }
    out
}

const PCI: Option<(u16, u16)> = Some((0x1d0f, 0x8061));

#[test]
fn identity_needs_the_serial_model_and_pci_identity_of_the_recorded_volume() {
    let model = field::<40>("Amazon Elastic Block Store", b' ');
    for serial in [field::<20>("vol0abc", b' '), field::<20>("vol0abc", 0)] {
        assert!(
            identity_matches(&serial, &model, PCI, "vol0abc"),
            "space or NUL padding"
        );
    }
    let serial = field::<20>("vol0abc", b' ');
    assert!(
        !identity_matches(&field::<20>("vol0abd", b' '), &model, PCI, "vol0abc"),
        "a reused BDF with another volume"
    );
    assert!(!identity_matches(
        &serial,
        &field::<40>("Amazon EC2 NVMe Instance Storage", b' '),
        PCI,
        "vol0abc"
    ));
    assert!(!identity_matches(
        &serial,
        &model,
        Some((0x1d0f, 0xcd00)),
        "vol0abc"
    ));
    assert!(!identity_matches(&serial, &model, None, "vol0abc"));
    assert!(
        !identity_matches(&field::<20>(" vol0abc", b' '), &model, PCI, "vol0abc"),
        "a leading space is part of the reported serial"
    );
    assert!(
        !identity_matches(&field::<20>("vol0abc\0x", 0), &model, PCI, "vol0abc"),
        "a byte after an interior NUL is part of the reported serial"
    );
}

#[test]
fn submit_errors_map_to_refusals_and_only_enxio_makes_the_driver_gone() {
    assert_eq!(
        refusal_for(-libc::ENOMEM),
        (RefusalReason::QueueFull, false)
    );
    assert_eq!(refusal_for(-libc::ENXIO), (RefusalReason::DeviceGone, true));
    assert_eq!(
        refusal_for(-libc::EINVAL),
        (RefusalReason::InvalidRange, false)
    );
    assert_eq!(
        refusal_for(-libc::EFAULT),
        (RefusalReason::InvalidRange, false)
    );
}

#[test]
fn only_valid_reads_with_en_and_rdy_clear_prove_the_disable() {
    let (en, rdy) = (1, 1);
    assert!(disable_proven(0x0046_0000, 0, en, rdy));
    for (cc, csts) in [
        (u32::MAX, 0),
        (0, u32::MAX),
        (0x0046_0001, 0),
        (0x0046_0000, 1),
        (u32::MAX, u32::MAX),
    ] {
        assert!(!disable_proven(cc, csts, en, rdy), "{cc:#x} {csts:#x}");
    }
}

#[test]
fn a_refused_disconnect_is_a_failure_and_a_running_one_is_pending() {
    assert_eq!(disconnect_outcome(0), QuiesceStatus::Pending);
    assert_eq!(disconnect_outcome(-libc::EBUSY), QuiesceStatus::Pending);
    assert_eq!(
        disconnect_outcome(-libc::ENXIO),
        QuiesceStatus::Failed(Some(libc::ENXIO))
    );
}

#[test]
fn a_zero_depth_or_timeout_threshold_is_refused() {
    let good = SpdkConfig {
        queue_depth: 8,
        timeout_io_us: 1,
        timeout_admin_us: 1,
    };
    assert!(good.is_valid());
    for bad in [
        SpdkConfig {
            queue_depth: 0,
            ..good
        },
        SpdkConfig {
            timeout_io_us: 0,
            ..good
        },
        SpdkConfig {
            timeout_admin_us: 0,
            ..good
        },
    ] {
        assert!(!bad.is_valid(), "{bad:?}");
    }
}
