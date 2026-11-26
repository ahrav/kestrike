//! The SPDK driver's decisions over native results, kept apart from the
//! native calls so each rule is checked on its own.

use super::super::disk::{QuiesceStatus, RefusalReason};
use super::super::identify::identify_text;
use crate::bind::ControllerIdentity;

/// Whether the live controller is the recorded EBS volume: its serial, model
/// and PCI identity, with the serial and model read by the same rule that
/// decodes them into [`IdentifyFacts`](super::super::IdentifyFacts).
pub(crate) fn identity_matches(
    serial: &[i8],
    model: &[i8],
    pci: Option<(u16, u16)>,
    expected_serial: &str,
) -> bool {
    let text = |field: &[i8]| identify_text(&field.iter().map(|&b| b as u8).collect::<Vec<_>>());
    text(serial).is_ok_and(|serial| serial == expected_serial)
        && text(model).is_ok_and(|model| model == ControllerIdentity::EBS.model)
        && pci == Some(ControllerIdentity::EBS.pci)
}

/// The refusal for a nonzero `spdk_nvme_ns_cmd_*` result, and whether it
/// makes the driver gone. SPDK queued nothing for any of them: `-ENOMEM` is
/// an exhausted request pool, `-ENXIO` a failed or removed qpair, and any
/// other error a request SPDK could not build.
pub(crate) fn refusal_for(rc: i32) -> (RefusalReason, bool) {
    match -rc {
        libc::ENOMEM => (RefusalReason::QueueFull, false),
        libc::ENXIO => (RefusalReason::DeviceGone, true),
        _ => (RefusalReason::InvalidRange, false),
    }
}

/// What starting the controller disable proved: nothing yet, or a failure
/// when SPDK refused to start it for a reason other than a disable already
/// in progress (`-EBUSY`). Either way the register reads decide later.
pub(crate) fn disconnect_outcome(rc: i32) -> QuiesceStatus {
    if rc == 0 || rc == -libc::EBUSY {
        QuiesceStatus::Pending
    } else {
        QuiesceStatus::Failed(Some(-rc))
    }
}
