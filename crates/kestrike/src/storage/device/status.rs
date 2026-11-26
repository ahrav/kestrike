//! Raw device completion status, transfer classification, deposition detection and the mid-tenure [`ControllerEvent`] a status shows.
//!
//! A driver reports status exactly as the device produced it; classification happens once, here, so no driver can call a short transfer a success.
//! A successful write status records the device's acknowledgement of the transfer. The only route from a completion to a durability fact is a [`PersistenceProfile`](super::PersistenceProfile) derived for the attached device: under it, persistence evidence for a write must be an explicit event recorded after the write's completion is delivered and before the write's object is published, and after the event of each write it depends on.

use crate::failover::evidence::{PREEMPT_ABORTED, RESERVATION_CONFLICT};

/// A completion's status exactly as the device wrote it.
///
/// `repr(u32)` fixes the layout: a `u32` tag at offset 0, the payload at offset 4, and 8 bytes in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DeviceStatus {
    /// Bits 31:16 of NVMe completion dword 3: phase (bit 0), status code (bits 8:1), status code type (bits 11:9), then retry delay, more and do-not-retry.
    Nvme(u16),
    /// A kernel I/O result: bytes transferred when non-negative, a negated `errno` otherwise.
    Kernel(i32),
}

/// What a completion means for its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// The whole requested length transferred.
    Success,
    /// Fewer bytes than requested transferred. This is a failure for reads and writes; `transferred` is diagnostic and nothing resumes the transfer.
    Short { transferred: u32 },
    /// The device reported an error, or a result no request can produce.
    Failed,
}

/// Status code and status code type bits of the NVMe status field; the phase bit and the retry and more flags are outside it.
const NVME_STATUS_MASK: u16 = 0x0FFE;

impl DeviceStatus {
    /// The status code of an NVMe completion whose status code type is generic (0); `None` for another type or a kernel result.
    pub fn generic_code(self) -> Option<u16> {
        match self {
            Self::Nvme(raw) if raw & 0x0E00 == 0 => Some((raw >> 1) & 255),
            Self::Nvme(_) | Self::Kernel(_) => None,
        }
    }

    /// Only generic reservation conflict (0x83) and preempt abort (0x1b) certify deposition.
    pub fn deposes(self) -> bool {
        matches!(
            self.generic_code(),
            Some(RESERVATION_CONFLICT | PREEMPT_ABORTED)
        )
    }

    /// Classifies a completion for a command that requested `requested` bytes.
    /// NVMe succeeds only when status code and status code type are both zero, and has no partial success.
    /// A kernel result succeeds only when it equals `requested`; a smaller non-negative result is `Short`; a negative or larger one is `Failed`.
    #[inline]
    pub fn classify(self, requested: u32) -> Classification {
        match self {
            Self::Nvme(raw) if raw & NVME_STATUS_MASK == 0 => Classification::Success,
            Self::Nvme(_) => Classification::Failed,
            Self::Kernel(result) => match u32::try_from(result) {
                Ok(done) if done == requested => Classification::Success,
                Ok(transferred) if transferred < requested => Classification::Short { transferred },
                Ok(_) | Err(_) => Classification::Failed,
            },
        }
    }
}

/// A mid-tenure controller event, which ends the incarnation: the owner stops submitting, tears down the queues,
/// discards its index and runs the restart sequence again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerEvent {
    /// A controller reset, a function-level reset, or a controller disable or shutdown: the driver observes a failed
    /// controller or queue.
    Reset,
    /// A command completed with status Command Abort Requested (generic 0x07).
    Abort,
    /// A command completed with status Command Aborted due to SQ Deletion (generic 0x08).
    QueueDelete,
}

impl ControllerEvent {
    /// The event a command's completion status shows, if any.
    pub fn of_status(status: DeviceStatus) -> Option<Self> {
        const ABORT_REQUESTED: u16 = 0x07;
        const SQ_DELETION: u16 = 0x08;
        match status.generic_code()? {
            ABORT_REQUESTED => Some(Self::Abort),
            SQ_DELETION => Some(Self::QueueDelete),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Classification, ControllerEvent, DeviceStatus};

    const LEN: u32 = 16384;

    #[test]
    fn only_generic_abort_and_sq_deletion_codes_show_a_controller_event() {
        for raw in 0..=u16::MAX {
            let (sc, sct) = ((raw >> 1) & 255, (raw >> 9) & 7);
            let expected = match (sct, sc) {
                (0, 0x07) => Some(ControllerEvent::Abort),
                (0, 0x08) => Some(ControllerEvent::QueueDelete),
                _ => None,
            };
            assert_eq!(
                ControllerEvent::of_status(DeviceStatus::Nvme(raw)),
                expected,
                "{raw:#06x}"
            );
        }
        for result in [-4, 0, 0x07, 0x08 << 1] {
            assert_eq!(
                ControllerEvent::of_status(DeviceStatus::Kernel(result)),
                None
            );
        }
    }

    /// Every NVMe status word classifies from its status code (bits 8:1)
    /// and status code type (bits 11:9) alone. A word succeeds when both
    /// are zero, for any phase, retry delay, more and do-not-retry bits and
    /// any requested length, so 32 of the 65,536 words succeed.
    #[test]
    fn every_nvme_status_word_classifies_by_its_code_and_type_alone() {
        let mut successes = 0;
        for raw in 0..=u16::MAX {
            let (sc, sct) = ((raw >> 1) & 255, (raw >> 9) & 7);
            let expected = if sc == 0 && sct == 0 {
                successes += 1;
                Classification::Success
            } else {
                Classification::Failed
            };
            assert_eq!(
                DeviceStatus::Nvme(raw).classify(LEN),
                expected,
                "{raw:#06x}"
            );
            assert_eq!(DeviceStatus::Nvme(raw).classify(0), expected, "{raw:#06x}");
        }
        assert_eq!(successes, 32);
    }

    #[test]
    fn classification_follows_the_status_rules() {
        let cases = [
            (DeviceStatus::Nvme(0x0000), Classification::Success),
            (DeviceStatus::Nvme(0x0001), Classification::Success),
            (DeviceStatus::Nvme(0xF001), Classification::Success),
            (DeviceStatus::Nvme(0x0004), Classification::Failed),
            (DeviceStatus::Nvme(0x0002), Classification::Failed),
            (DeviceStatus::Nvme(0x0200), Classification::Failed),
            (DeviceStatus::Nvme(0x0400), Classification::Failed),
            (DeviceStatus::Nvme(0x0800), Classification::Failed),
            (DeviceStatus::Nvme(0x0E01), Classification::Failed),
            (DeviceStatus::Kernel(LEN as i32), Classification::Success),
            (
                DeviceStatus::Kernel(LEN as i32 - 4096),
                Classification::Short {
                    transferred: LEN - 4096,
                },
            ),
            (
                DeviceStatus::Kernel(0),
                Classification::Short { transferred: 0 },
            ),
            (DeviceStatus::Kernel(-5), Classification::Failed),
            (DeviceStatus::Kernel(LEN as i32 + 1), Classification::Failed),
            (DeviceStatus::Kernel(i32::MIN), Classification::Failed),
        ];
        for (status, expected) in cases {
            assert_eq!(status.classify(LEN), expected, "{status:?}");
        }
    }
}
