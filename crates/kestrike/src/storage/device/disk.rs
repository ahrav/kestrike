//! The storage driver seam: one `unsafe` trait a driver implements and the value types that cross it.
//!
//! Invariants the seam carries:
//!
//! - Submission is non-blocking and either refused, with the device never touching the command's memory, or accepted, with exactly one completion to follow unless a proven stop comes first.
//! - A completion reaches the caller only after the device's access to its memory ended and its writes are visible to the polling thread.
//! - A pick pushes into a [`CompletionSink`] whose limit never exceeds its vector's spare capacity, so delivery never allocates, and a refused push keeps the completion in the device.
//! - Status passes through exactly as the device produced it; [`DeviceStatus::classify`] interprets transfer success and [`DeviceStatus::deposes`] interprets deposition.
//! - Only [`QuiesceStatus::Stopped`] proves that device access to host memory ended.

use std::ptr::NonNull;

use super::geometry::{DeviceGeometry, DeviceRange};
use super::identify::AttachFacts;
use super::reservation::{ReservationCommand, ReservationLimits};
use super::status::DeviceStatus;

/// The caller's name for one submitted command, echoed unchanged in its completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandToken(u64);

impl CommandToken {
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Host memory for one command: the prefix of one arena buffer.
///
/// `addr` carries the arena backing's provenance and equals the backing base plus `offset`, and `offset + len` lies inside the backing, so a driver may address the range by pointer or by offset into a registration of the whole backing.
/// Holding a range grants no access; only a driver inside an accepted command may touch the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaRange {
    addr: NonNull<u8>,
    offset: usize,
    len: u32,
}

impl DmaRange {
    /// Describes `len` bytes at `addr`, `offset` bytes into the backing.
    /// The caller has checked that the bytes are one buffer's prefix.
    pub(crate) fn new(addr: NonNull<u8>, offset: usize, len: u32) -> Self {
        Self { addr, offset, len }
    }

    pub fn addr(&self) -> NonNull<u8> {
        self.addr
    }

    /// Bytes from the arena backing's base to the range's start, a multiple of [`IO_UNIT`](super::IO_UNIT).
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Data commands use a positive sector multiple; reservation payloads use 16 bytes or an extended Report length divisible by 64.
    pub fn byte_len(&self) -> u32 {
        self.len
    }
}

/// Why a driver refused a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    /// The device holds as many outstanding commands as it can.
    QueueFull,
    /// The range breaks a limit of this driver or device.
    InvalidRange,
    /// The device is gone or stopped, and will accept nothing again.
    DeviceGone,
    /// The driver has no verified arena range for the command; an attach authority withholds its reads and writes
    /// until a gate pass for the own pair; or a reservation command names a key or pair other than the attach
    /// authority's, or carries payload bytes that do not encode the command.
    NotVerified,
    /// This driver supports data commands only.
    Unsupported,
}

/// A refused submission, with the driver's own code when it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubmitRefusal {
    pub reason: RefusalReason,
    pub code: Option<i32>,
}

/// One finished command.
///
/// `repr(C)` keeps the declared field order: `token` at offset 0, `status` at offset 8, 16 bytes in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Completion {
    pub token: CommandToken,
    pub status: DeviceStatus,
}

/// The only way a driver hands completions to its caller: pushes into the caller's vector, refused once `limit` pushes have landed.
/// The limit is clamped to the vector's spare capacity, so a push never reallocates.
#[derive(Debug)]
pub struct CompletionSink<'a> {
    out: &'a mut Vec<Completion>,
    remaining: usize,
    refused: usize,
}

impl<'a> CompletionSink<'a> {
    /// A sink accepting at most `limit` completions, and never more than `out` has spare capacity for.
    #[inline]
    pub fn new(out: &'a mut Vec<Completion>, limit: usize) -> Self {
        let remaining = limit.min(out.capacity() - out.len());
        Self {
            out,
            remaining,
            refused: 0,
        }
    }

    /// Pushes one completion.
    ///
    /// # Errors
    ///
    /// The completion back, counted as refused, once the limit is reached; the driver keeps it for a later pick.
    #[inline]
    pub fn push(&mut self, completion: Completion) -> Result<(), Completion> {
        // `remaining` never exceeds the spare capacity, so the second test only tells the compiler that the push below never reallocates.
        if self.remaining == 0 || self.out.len() == self.out.capacity() {
            self.refused += 1;
            return Err(completion);
        }
        self.remaining -= 1;
        self.out.push(completion);
        Ok(())
    }

    /// Pushes the sink still accepts.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Pushes the sink refused.
    pub fn refused(&self) -> usize {
        self.refused
    }
}

/// What a quiesce request proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuiesceStatus {
    /// The driver observed a reset or queue deletion complete, or observed every accepted command's completion delivered; see the `I6` guarantee on [`Disk`].
    Stopped,
    /// Commands may still be in flight; nothing is proven.
    Pending,
    /// The attempt failed, with the driver's code when it has one; nothing is proven.
    Failed(Option<i32>),
}

/// A storage device driver.
///
/// # Safety
///
/// Safe code frees and reuses host memory on the strength of these guarantees, so an implementation must uphold every one:
///
/// - **I1.** An `Err` from a submit means the device never received the command and will never touch its memory; the token is not outstanding.
/// - **I2.** After an `Ok`, the driver reports exactly one completion for the token through [`pick_completions`](Self::pick_completions), unless a later [`quiesce`](Self::quiesce) returns `Stopped` first. It never reports a token that is not outstanding.
/// - **I3.** A read writes only inside its memory range; a write only reads it; neither touches memory outside it.
/// - **I4.** A completion is pushed only after every device access to its command's memory ended and the device's writes are visible to the thread calling `pick_completions`; the implementation supplies whatever ordering that takes.
/// - **I5.** A pick pushes at most the sink's remaining capacity and never discards a completion taken from the device; one the sink refuses stays with the driver for a later pick.
/// - **I6.** `Stopped` follows an observed, not merely issued, reset or queue deletion, or an observation that every accepted command's completion was delivered. No command accepted before the call can access memory again or be reported afterwards, the device's earlier writes are visible to the caller, and every later submit is refused `DeviceGone`. `Pending` and `Failed` prove nothing. `Stopped` overrides I5 for a completion taken from the device but not yet pushed.
/// - **I7.** Status passes through exactly as the device produced it, and [`geometry`](Self::geometry) is constant for the driver's life.
/// - **I8.** The driver performs no device access outside an accepted command's range and keeps no host-side accounting of buffer ownership. Holding the arena's registration borrow is allowed.
/// - **I9.** Each value of the implementing type owns its command queue: a command accepted through one value is reported only through that value, and never through another value or a later borrow of the same device after the first is dropped. A handle type that shares a device, such as `&mut Driver`, cannot uphold this.
/// - **I10.** A submit that unwinds leaves its command possibly accepted: the device may still access its memory and a later pick may report its token, and a `quiesce` that returns `Stopped` ends that access as I6 ends an accepted command's. The driver stays usable for later picks and quiesce calls.
///
/// A `quiesce` that returns `Stopped` proves that device access has ended (I6). A driver whose `Drop` frees device resources resets the controller first, or documents that outstanding commands may write the arena until the process exits.
///
/// A safe `impl` does not compile:
///
/// ```compile_fail,E0200
/// use kestrike::storage::{
///     CommandToken, CompletionSink, DeviceGeometry, DeviceRange, Disk, DmaRange, QuiesceStatus,
///     SubmitRefusal,
/// };
///
/// struct Bogus;
///
/// impl Disk for Bogus {
///     fn geometry(&self) -> DeviceGeometry {
///         DeviceGeometry { capacity: 4096, max_transfer: 4096, block_size: 4096, queue_depth: 1 }
///     }
///     unsafe fn submit_read(&mut self, _: CommandToken, _: DeviceRange, _: DmaRange) -> Result<(), SubmitRefusal> {
///         Ok(())
///     }
///     unsafe fn submit_write(&mut self, _: CommandToken, _: DeviceRange, _: DmaRange) -> Result<(), SubmitRefusal> {
///         Ok(())
///     }
///     fn pick_completions(&mut self, _: &mut CompletionSink<'_>) {}
///     fn quiesce(&mut self) -> QuiesceStatus {
///         QuiesceStatus::Pending
///     }
/// }
/// ```
///
/// The same signatures under `unsafe impl` compile:
///
/// ```
/// use kestrike::storage::{
///     CommandToken, CompletionSink, DeviceGeometry, DeviceRange, Disk, DmaRange, QuiesceStatus,
///     SubmitRefusal,
/// };
///
/// struct Bogus;
///
/// // SAFETY: never called; the block checks signatures only.
/// unsafe impl Disk for Bogus {
///     fn geometry(&self) -> DeviceGeometry {
///         DeviceGeometry { capacity: 4096, max_transfer: 4096, block_size: 4096, queue_depth: 1 }
///     }
///     unsafe fn submit_read(&mut self, _: CommandToken, _: DeviceRange, _: DmaRange) -> Result<(), SubmitRefusal> {
///         Ok(())
///     }
///     unsafe fn submit_write(&mut self, _: CommandToken, _: DeviceRange, _: DmaRange) -> Result<(), SubmitRefusal> {
///         Ok(())
///     }
///     fn pick_completions(&mut self, _: &mut CompletionSink<'_>) {}
///     fn quiesce(&mut self) -> QuiesceStatus {
///         QuiesceStatus::Pending
///     }
/// }
/// ```
pub unsafe trait Disk {
    /// The device's shape, constant for the driver's life (I7).
    fn geometry(&self) -> DeviceGeometry;

    /// Submits a read of `device` into `memory` without blocking.
    ///
    /// # Safety
    ///
    /// Every Rust reference to `memory`'s bytes has ended before the call.
    /// If the call returns `Ok`, `memory` stays mapped, and no reference to its bytes is formed and no other path reads or writes them, until this token's completion is picked or a quiesce returns `Stopped`.
    /// If it returns `Err`, the obligation ends at once.
    /// `memory` and `device` have the same length, a multiple of the geometry's block size, and `token` is unique among this driver's outstanding tokens.
    /// The command ends, by a picked completion or a proven stop, before the driver passes to any other code that submits through it, such as a [`CommandTable`](super::CommandTable), whose tokens could then repeat this one.
    ///
    /// # Errors
    ///
    /// A [`SubmitRefusal`]; the device never received the command (I1).
    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal>;

    /// Submits a write of `memory` to `device` without blocking.
    ///
    /// # Safety
    ///
    /// As for [`submit_read`](Self::submit_read).
    ///
    /// # Errors
    ///
    /// A [`SubmitRefusal`]; the device never received the command (I1).
    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal>;

    /// Reservation capacity, constant for the driver's life and read from driver-owned data, including after stop or detach.
    /// Returning `Some` requires an implementation of `submit_reservation` supporting those limits and of `check_reservation_report`.
    /// A volume's attach gate runs through these commands, so outside test builds `None` ends the attach bootstrap `Unfenced(Unsupported)` before any medium command.
    fn reservation_limits(&self) -> Option<ReservationLimits> {
        None
    }

    /// `reservation_report` exposes a completed Report only after the driver's identity check returns `Ok` for the Report's bytes.
    ///
    /// # Errors
    ///
    /// When the check returns a [`ReportError`](super::reservation::ReportError) for a successful Report, `reservation_report` withholds the Report and the crate's `refused_report` exposes its bytes. The default returns `Unchecked`.
    fn check_reservation_report(
        &self,
        _bytes: &[u8],
    ) -> Result<(), super::reservation::ReportError> {
        Err(super::reservation::ReportError::Unchecked)
    }

    /// Submits one reservation command on the same owned queue as data commands.
    ///
    /// # Safety
    ///
    /// The memory and token obey the lifetime, exclusivity and finality requirements of `submit_read`. Its length is the command length from the validated limits; Register, Acquire, both Preempt-and-Abort forms and the ended-key Preempt read the first 16 bytes, and Report writes its entire range.
    unsafe fn submit_reservation(
        &mut self,
        _token: CommandToken,
        _command: ReservationCommand,
        _memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        Err(SubmitRefusal {
            reason: RefusalReason::Unsupported,
            code: None,
        })
    }

    /// Moves finished commands into `sink` without blocking, within its remaining capacity (I5).
    /// Any caller may call it: a missed pick leaves a buffer owned forever and never frees one, so the method is safe.
    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>);

    /// A gate value exists once Register, type-2 Acquire and Report have shown the own pair as the one holder and the
    /// one registrant, or the restart Report #2 an authority carries has shown it as the one holder with every other
    /// registrant a recorded pair. The volume passes its value at its gate, and before the volume exists the fresh
    /// first acquisition's fencer passes its value before each unit-0 write and read, so a driver receives the call
    /// more than once. A driver that enabled reservations installs the reservation gate's range as its data range
    /// here; one whose attach authority withholds reads and writes also opens them; a repeated value changes nothing
    /// further; the default ignores the call.
    fn admit_medium(&mut self, _gate: &crate::storage::Fenced) {}

    /// Asks the device to stop accessing host memory, and reports what that proved (I6).
    /// The call does bounded work and never waits: while a stop is requested but not yet observed it returns `Pending`, and a later call observes the progress.
    fn quiesce(&mut self) -> QuiesceStatus;

    /// Runs driver housekeeping that may block the calling thread until the device answers, such as polling an admin queue.
    /// The owner schedules `service` separately from latency-sensitive `pick_completions` calls.
    /// Completions reach the caller only through [`pick_completions`](Self::pick_completions) (I2).
    fn service(&mut self) {}

    /// The device and Identify data the driver established at attach, if it captured any; constant for the driver's life.
    /// An implementation reads only data it owns and stays callable after a stop or detach: the table exposes the method in every admission state, including after a proven stop.
    fn attach_facts(&self) -> Option<&AttachFacts> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandToken, Completion, CompletionSink};
    use crate::storage::device::status::DeviceStatus;

    fn completion(raw: u64) -> Completion {
        Completion {
            token: CommandToken::from_raw(raw),
            status: DeviceStatus::Nvme(0),
        }
    }

    #[test]
    fn a_sink_refuses_past_its_limit_counts_refusals_and_never_grows_its_vector() {
        let mut out = Vec::with_capacity(4);
        out.push(completion(0));
        {
            let mut sink = CompletionSink::new(&mut out, 8);
            assert_eq!(sink.remaining(), 3);
            for raw in 1..=3 {
                assert_eq!(sink.push(completion(raw)), Ok(()));
            }
            assert_eq!(sink.push(completion(4)), Err(completion(4)));
            assert_eq!(sink.push(completion(5)), Err(completion(5)));
            assert_eq!((sink.remaining(), sink.refused()), (0, 2));
        }
        assert_eq!(out.capacity(), 4);
        assert_eq!(out, (0..4).map(completion).collect::<Vec<_>>());
        let mut sink = CompletionSink::new(&mut out, 8);
        assert_eq!(sink.remaining(), 0);
        assert!(sink.push(completion(9)).is_err());
        // A limit below the spare capacity binds, and a zero limit refuses the first push.
        let mut roomy = Vec::with_capacity(8);
        let mut sink = CompletionSink::new(&mut roomy, 2);
        assert_eq!(sink.push(completion(1)), Ok(()));
        assert_eq!(sink.push(completion(2)), Ok(()));
        assert_eq!(sink.push(completion(3)), Err(completion(3)));
        assert_eq!(sink.refused(), 1);
        assert_eq!(roomy.len(), 2);
        let mut sink = CompletionSink::new(&mut roomy, 0);
        assert_eq!(sink.push(completion(4)), Err(completion(4)));
        assert_eq!(sink.refused(), 1);
        assert_eq!((roomy.len(), roomy.capacity()), (2, 8));
    }
}
