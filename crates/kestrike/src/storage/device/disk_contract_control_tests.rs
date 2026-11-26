//! Controls for the disk contract: each runs the unchanged contract over a
//! simulated device with one guarantee broken and fails through the
//! assertion that guards it.
//!
//! The agreed property: every `Disk` implementation meets the invariants I1
//! to I7 of the trait's `# Safety` section as a caller observes them.
//! `disk_contract` checks those invariants, and checks that the device
//! refuses a submit past the capacity and at the queue depth. Each control
//! wraps a `SimDisk` in [`Broken`], which applies one [`Plant`] in its
//! `Disk` methods. The cases cover the refusals past the capacity and at
//! the queue depth, a repeated and a foreign completion (I2), a completion
//! the sink refused and the device dropped (I5), a completion and an
//! accepted submit after the stop proof (I6), and a changed geometry (I7).
//!
//! No negative control targets these contract assertion sites: "a refused
//! command wrote its memory", "a stopped command wrote its memory", "the
//! device proved its stop", "a pick reported a token that is not
//! outstanding" at the pick before the stop while the last read is
//! outstanding, "read {index} wrote past its range" in the read phase, each
//! `Success` classification, each refusal reason, including refusals after
//! the stop, and the "the accepted submit" wait. The late-store controls in
//! `sim_tests` target "changed its buffer after its completion", "changed
//! its source by its completion", "returned block 0 changed", "reads back
//! as written" and the stop phase's "wrote past its range". The sink's type
//! enforces the full-sink check: `CompletionSink::push` refuses every
//! completion when the sink has zero spare slots.

use std::cell::Cell;
use std::time::Duration;

use super::sim::{Mode, QuiesceMode, SimControl, SimDisk, sim};
use super::sim_tests::{arena, config, pick};
use super::{
    CommandToken, Completion, CompletionSink, DeviceGeometry, DeviceRange, DeviceStatus, Disk,
    DmaRange, IO_UNIT, QuiesceStatus, RefusalReason, SubmitRefusal,
};

/// The one guarantee a [`Broken`] device breaks.
#[derive(Clone, Copy)]
enum Plant {
    /// Accepts the first submit the simulated device refuses for this reason and reports a success for it at the next pick.
    AcceptRefused(RefusalReason),
    /// Reports the first completion the simulated device delivers again at the next pick.
    Duplicate,
    /// Reports [`FOREIGN`] at the first pick with room while nothing is outstanding and before the stop.
    Foreign,
    /// Takes one completion from the simulated device at the first pick into a full sink and discards it.
    DropRefused,
    /// Takes the completion the simulated device posted before the first quiesce and reports it at the first pick after.
    AfterStop,
    /// Accepts every submit after a quiesce answered `Stopped` and forwards none.
    AcceptAfterStop,
    /// Reports a capacity one I/O unit larger on the second geometry read.
    Geometry,
}

/// The simulated device behind one [`Plant`].
struct Broken {
    disk: SimDisk,
    control: SimControl,
    plant: Plant,
    /// A completion the device reports at its next pick with room, before the simulated device's.
    queued: Option<Completion>,
    /// Whether a one-shot plant took effect.
    planted: bool,
    stopped: bool,
    geometry_reads: Cell<usize>,
}

/// A token from phase 7, past every phase the contract submits.
const FOREIGN: CommandToken = CommandToken::from_raw(7 << 32);

fn success(token: CommandToken) -> Completion {
    Completion {
        token,
        status: DeviceStatus::Kernel(IO_UNIT as i32),
    }
}

impl Broken {
    fn submit(
        &mut self,
        token: CommandToken,
        forward: impl FnOnce(&mut SimDisk) -> Result<(), SubmitRefusal>,
    ) -> Result<(), SubmitRefusal> {
        if self.stopped && matches!(self.plant, Plant::AcceptAfterStop) {
            return Ok(());
        }
        match (self.plant, forward(&mut self.disk)) {
            (Plant::AcceptRefused(reason), Err(refusal))
                if refusal.reason == reason && !self.planted =>
            {
                self.planted = true;
                self.queued = Some(success(token));
                Ok(())
            }
            (_, result) => result,
        }
    }
}

// SAFETY: The simulated device upholds the `Disk` guarantees. On the first refusal with `refusal.reason == reason`, `AcceptRefused(reason)` reports acceptance and fabricates a `Success` for the refused token (I7). `Duplicate` repeats a completion; `Foreign` reports a token outside the submitted set (I2). `DropRefused` discards a completion when the sink is full (I5). After `Stopped`, `AfterStop` reports a completion and `AcceptAfterStop` accepts submissions (I6). `Geometry` changes the reported geometry (I7). The contract forms byte views only after refusal, delivery, or a proven stop, or for buffers the simulated device never received. The simulated device alone accesses buffers synchronously on the test thread during driver and control calls. Those accesses end before the contract unwinds.
unsafe impl Disk for Broken {
    fn geometry(&self) -> DeviceGeometry {
        let geometry = self.disk.geometry();
        let reads = self.geometry_reads.replace(self.geometry_reads.get() + 1);
        if matches!(self.plant, Plant::Geometry) && reads == 1 {
            return DeviceGeometry {
                capacity: geometry.capacity + IO_UNIT as u64,
                ..geometry
            };
        }
        geometry
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's obligations pass through unchanged.
        self.submit(token, |disk| unsafe {
            disk.submit_read(token, device, memory)
        })
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's obligations pass through unchanged.
        self.submit(token, |disk| unsafe {
            disk.submit_write(token, device, memory)
        })
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        if !self.planted {
            match self.plant {
                Plant::Foreign
                    if !self.stopped && sink.remaining() > 0 && self.control.outstanding() == 0 =>
                {
                    self.planted = true;
                    self.queued = Some(success(FOREIGN));
                }
                Plant::DropRefused if sink.remaining() == 0 => {
                    self.planted = true;
                    pick(&mut self.disk, 1);
                    return;
                }
                _ => {}
            }
        }
        if sink.remaining() > 0
            && let Some(completion) = self.queued.take()
        {
            sink.push(completion).expect("the sink has room");
            return;
        }
        let (out, _) = pick(&mut self.disk, sink.remaining());
        if matches!(self.plant, Plant::Duplicate)
            && !self.planted
            && let Some(first) = out.first()
        {
            self.planted = true;
            self.queued = Some(*first);
        }
        for done in out {
            sink.push(done).expect("the sink has room for every pick");
        }
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        if matches!(self.plant, Plant::AfterStop) && !self.planted {
            self.planted = true;
            self.queued = pick(&mut self.disk, 1).0.pop();
        }
        let status = self.disk.quiesce();
        self.stopped |= status == QuiesceStatus::Stopped;
        status
    }
}

/// Runs the unchanged contract over the simulated device behind `plant`,
/// under `QuiesceMode::Reset`, with the device moving between picks.
fn broken_contract(plant: Plant) {
    let arena = arena();
    let (disk, control) = sim(config(37, Mode::Direct));
    control.set_quiesce(QuiesceMode::Reset);
    let mut disk = Broken {
        disk,
        control: control.clone(),
        plant,
        queued: None,
        planted: false,
        stopped: false,
        geometry_reads: Cell::new(0),
    };
    // SAFETY: the simulated device reaches the buffers only on this thread inside driver and control calls, so an unwind leaves no access in flight.
    unsafe {
        super::disk_contract::meets_the_disk_contract(&mut disk, &arena, Duration::ZERO, || {
            control.tick(u32::MAX);
        });
    }
}

/// Accepting the read past the capacity fails the refusal check once the
/// fabricated completion arrives.
#[test]
#[should_panic(expected = "a submit the contract expects refused InvalidRange was accepted")]
fn a_device_that_accepts_a_read_past_its_capacity_fails_the_disk_contract() {
    broken_contract(Plant::AcceptRefused(RefusalReason::InvalidRange));
}

/// Accepting the read at the queue depth fails the refusal check once its
/// completion arrives with the held reads.
#[test]
#[should_panic(expected = "a submit the contract expects refused QueueFull was accepted")]
fn a_device_that_accepts_a_read_at_its_queue_depth_fails_the_disk_contract() {
    broken_contract(Plant::AcceptRefused(RefusalReason::QueueFull));
}

/// A write's completion repeated inside the writes' drain fills the drain's
/// count before the last write arrives, which fails the once-only check.
#[test]
#[should_panic(expected = "each accepted command completes once")]
fn a_device_that_reports_a_token_twice_fails_the_disk_contract() {
    broken_contract(Plant::Duplicate);
}

/// A phase-7 token reported while nothing is outstanding fails the idle
/// check after the writes, which prints that token.
#[test]
#[should_panic(expected = "without a command: [Completion { token: CommandToken(30064771072)")]
fn a_device_that_reports_a_token_never_submitted_fails_the_disk_contract() {
    broken_contract(Plant::Foreign);
}

/// A write completion discarded at the pick into a sink with no room leaves
/// the writes' drain short after its 2^20 picks.
#[test]
#[should_panic(expected = "the contract's commands: 3 of 4 completions arrived")]
fn a_device_that_drops_a_completion_the_sink_refused_fails_the_disk_contract() {
    broken_contract(Plant::DropRefused);
}

/// The completion of the read the stop proof covers, reported at the first
/// pick after `Stopped`, fails the silence check, which prints its token.
#[test]
#[should_panic(expected = "without a command: [Completion { token: CommandToken(25769803776)")]
fn a_device_that_reports_a_completion_after_its_stop_fails_the_disk_contract() {
    broken_contract(Plant::AfterStop);
}

/// A submit accepted after `Stopped` fails the contract's one `unwrap_err`.
#[test]
#[should_panic(expected = "called `Result::unwrap_err()` on an `Ok` value")]
fn a_device_that_accepts_a_submit_after_its_stop_fails_the_disk_contract() {
    broken_contract(Plant::AcceptAfterStop);
}

/// A capacity that changes between the contract's two geometry reads fails
/// the constant-geometry check.
#[test]
#[should_panic(expected = "the geometry is constant")]
fn a_device_whose_geometry_changes_fails_the_disk_contract() {
    broken_contract(Plant::Geometry);
}
