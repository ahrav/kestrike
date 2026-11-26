//! Warm recovery cycles on the bound EBS volume through the SPDK driver, one per recovery package: the controller reset
//! and the process-kill control of the reboot package. Each case runs `storage::warm_cycle` over the SPDK rig. Tenure
//! one fills and reads back 24 objects, captures them and writes its checkpoint through its own unit commands. The
//! package's fault ends it: the reset case closes the volume, asserts the close quiesced with every command returned,
//! then disables the controller, so the reset meets a quiesced volume. Tenure two attaches a new storage over the same
//! volume under the soak store's next session, loads the checkpoint warm, and serves every member of S its exact bytes,
//! while the object its coverage copy covers misses. The simulated rig runs the same cycle in every lane as the
//! uncredited proxy of both cases.
//!
//! Each tenure's authority is the soak store's fixture authority, as in the production attach case, and the shard
//! record and the coverage copy are harness-built. No `failover::restart::Device` drives the SPDK driver, so the
//! restart sequence's record checks, bump and Reports run only in the takeover history world; these cases check the
//! warm load, the allocator and the coverage check on the device. A host reboot ends the case's process along with
//! its host, so the reboot package runs here as its process-kill control. The process-kill case kills a child
//! that holds the device, with its controller enabled, inside the case, where the lane's kill custody marks no host.
//! In no-IOMMU mode that death leaves the child's DMA exposure unproven and the parent's later attach reset does not
//! undo it, so the process-kill rig registers its arena only under an IOMMU and refuses a no-IOMMU host before any
//! controller is enabled. Both profiles carry the `pending` disposition on every platform row, so the lane reports
//! them Inconclusive and credits neither.
//!
//! Each case prints its `observe: retained`, `observe: residual` and `observe: persisted` lines once its judge passed,
//! so a cycle that breaks a rule fails its case and prints none of them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::disk::SpdkDisk;
use super::{CONFIG, PATIENCE, TICK, Unreachable, bound, shut, start_under, stop, teardown};
use crate::bind::OwnerLock;
use crate::exact_child::{self, ExactChild, Outcome};
use crate::native::{ArenaRegistration, DmaPolicy, Environment, Watchdog};
use crate::storage::owner_fixture::TestPlatform;
use crate::storage::volume_fixture::close_and_release;
use crate::storage::warm_cycle::{
    Captured, Fault, Patience, Rig, RigVolume, Treatment, after, arena_on, before, judge,
    kill_witness, persisted, reset_witness, residuals, witness,
};
use crate::storage::{
    BufferArena, EngineBudget, Quiesced, ReadEvent, ServingAuthority, Storage, Volume,
};

const CHILD: &str = "storage::device::spdk::hardware_tests::warm_cycle::the_killed_owners_child_writes_its_checkpoint";
/// Bounds the parent's wait for the child's checkpoint and the child's park before it aborts.
const CHILD_DEADLINE: Duration = Duration::from_secs(600);

/// One SPDK driver per tenure on the bound volume, and the package's fault.
struct Spdk<'a, 'l> {
    lock: &'l OwnerLock,
    env: &'a Environment,
    arena: &'a BufferArena<TestPlatform>,
    registration: Option<ArenaRegistration<'a>>,
    fault: Fault,
}

impl<'a, 'l> Rig<'a> for Spdk<'a, 'l> {
    type Disk = SpdkDisk<'l>;

    const PATIENCE: Patience = Patience::Wall(PATIENCE);

    fn attach<'s>(
        &mut self,
        storage: &'s Storage<TestPlatform>,
        authority: ServingAuthority,
    ) -> RigVolume<'s, 'a, Self::Disk> {
        let (registration, disk) =
            start_under(self.lock, self.env, self.arena, CONFIG, dma(self.fault));
        self.registration = Some(registration);
        Volume::attach(
            storage,
            self.arena,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            authority,
            8,
            TICK,
            &mut EngineBudget::new(1 << 25),
        )
        .map_err(|(error, _)| error)
        .unwrap()
    }

    fn step(&mut self, volume: &mut RigVolume<'_, 'a, Self::Disk>, out: &mut Vec<ReadEvent<'a>>) {
        let _ = volume.poll_storage(0, out);
    }

    fn fault(&mut self, volume: RigVolume<'_, 'a, Self::Disk>, captured: Captured) {
        match self.fault {
            Fault::ControllerReset => {
                let (started, mut out) = (Instant::now(), Vec::with_capacity(8));
                let (quiesced, mut disk) = close_and_release(
                    volume,
                    |ticks| Self::PATIENCE.allows(ticks, started.elapsed()),
                    |volume| {
                        let _ = volume.poll_storage(0, &mut out);
                        out.clear();
                    },
                );
                assert_eq!(
                    quiesced,
                    Quiesced::AllReturned,
                    "every command returned before the disable"
                );
                stop(&mut disk);
                let report = disk.witness().stop.expect("the disable read the registers");
                assert!(
                    report.proven && report.cc & 1 == 0 && report.csts & 1 == 0,
                    "CC.EN and CSTS.RDY read zero: {report:?}"
                );
                eprintln!(
                    "observe: {}",
                    reset_witness(report.cc, report.csts, &captured)
                );
                teardown(self.registration.take().expect("a registration"), &mut disk);
            }
            Fault::ProcessDeath => {
                exact_child::report(&captured.line());
                let start = Instant::now();
                while let Some(left) = CHILD_DEADLINE.checked_sub(start.elapsed()) {
                    std::thread::park_timeout(left);
                }
                // A child its parent never killed ends as abruptly as the kill would have ended it.
                std::process::abort();
            }
        }
    }

    fn close(&mut self, volume: RigVolume<'_, 'a, Self::Disk>) {
        shut(volume, self.registration.take().expect("a registration"));
    }
}

/// The DMA policy a rig registers its arena under. The process-kill rig's tenure dies with its controller enabled,
/// and in no-IOMMU mode neither that death nor a later controller reset proves its DMA stopped, so that rig registers
/// only under an IOMMU: on a no-IOMMU host its registration refuses before any controller is enabled.
fn dma(fault: Fault) -> DmaPolicy {
    DmaPolicy {
        allow_no_iommu: fault == Fault::ControllerReset,
    }
}

/// The process-kill rig refuses a no-IOMMU host at its arena registration, and the controller-reset rig, whose
/// close returns every command before the disable, keeps the no-IOMMU posture of the other volume cases.
#[test]
fn the_process_kill_rig_registers_only_under_an_iommu() {
    assert!(!dma(Fault::ProcessDeath).allow_no_iommu);
    assert!(dma(Fault::ControllerReset).allow_no_iommu);
}

fn finish(env: Environment, arena: BufferArena<TestPlatform>) {
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Unreachable)).unwrap();
    env.finish(&watchdog).unwrap();
    assert!(matches!(
        arena.release(),
        Ok(crate::storage::Released::Complete)
    ));
}

/// The episode the hardware lane names for this repeat, or `unset` for a run outside the lane.
fn episode() -> String {
    std::env::var("KESTRIKE_EPISODE").unwrap_or_else(|_| "unset".into())
}

/// After tenure one's fills, reads and checkpoint, its volume closes until every command returned and a
/// controller reset, proven by CC.EN and CSTS.RDY reading zero, ends it; tenure two loads the checkpoint warm on
/// the same volume and serves every member of S its exact bytes, while the covered object misses.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS"]
fn a_controller_reset_after_a_quiesced_close_keeps_the_retained_set_warm() {
    let (mut lock, env) = bound();
    let first = crate::soak::tenure_authority(&mut lock);
    let second = crate::soak::tenure_authority(&mut lock);
    let arena = arena_on(TestPlatform::linux());
    let mut rig = Spdk {
        lock: &lock,
        env: &env,
        arena: &arena,
        registration: None,
        fault: Fault::ControllerReset,
    };
    let captured = before(&mut rig, first);
    let retained = after(&mut rig, second, captured, Treatment::Warm);
    drop(rig);
    let episode = episode();
    judge(&retained).unwrap_or_else(|rule| panic!("{rule}: {}", witness(&retained, &episode)));
    eprintln!("observe: {}", witness(&retained, &episode));
    eprintln!("observe: {}", residuals(&retained));
    eprintln!("observe: {}", persisted(&captured, &retained));
    finish(env, arena);
}

/// The process-kill control: tenure one runs in a child process, and the case sends the child SIGKILL after the
/// child reports its checkpoint, with its volume attached and its controller enabled. Once the child is reaped,
/// tenure two attaches in this process, loads the checkpoint warm on the same volume and serves every member of S its
/// exact bytes, while the covered object misses. The child's report lines and its whole transcript go to stderr.
#[test]
#[ignore = "needs a disposable EBS volume bound by kestrike-bind, named by KESTRIKE_MAPPINGS, and the deployment owner's abrupt-death evidence"]
fn a_killed_owner_keeps_the_retained_set_warm_for_its_restart() {
    let mut child = ExactChild::spawn(CHILD, &[]).expect("spawn the owner's child");
    let until = Instant::now() + CHILD_DEADLINE;
    let captured = loop {
        let Some(line) = child.next_report(until) else {
            panic!(
                "the child reported no checkpoint: {:?}",
                child.finish(until)
            );
        };
        eprintln!("child report: {line}");
        if let Some(captured) = Captured::parse(&line) {
            break captured;
        }
    };
    let pid = child.id();
    let outcome = child.kill();
    for line in format!("{outcome:?}").lines() {
        eprintln!("child: {line}");
    }
    assert!(
        matches!(
            outcome,
            Outcome::Crashed {
                signal: libc::SIGKILL,
                ..
            }
        ),
        "the child died by SIGKILL"
    );
    eprintln!("observe: {}", kill_witness(pid, &captured));
    let (mut lock, env) = bound();
    let authority = crate::soak::tenure_authority(&mut lock);
    let arena = arena_on(TestPlatform::linux());
    let mut rig = Spdk {
        lock: &lock,
        env: &env,
        arena: &arena,
        registration: None,
        fault: Fault::ProcessDeath,
    };
    let retained = after(&mut rig, authority, captured, Treatment::Warm);
    drop(rig);
    let episode = episode();
    judge(&retained).unwrap_or_else(|rule| panic!("{rule}: {}", witness(&retained, &episode)));
    eprintln!("observe: {}", witness(&retained, &episode));
    eprintln!("observe: {}", residuals(&retained));
    eprintln!("observe: {}", persisted(&captured, &retained));
    finish(env, arena);
}

/// The killed owner's child: only in the child its parent spawned does this test call `before`, whose fault parks
/// for the parent's SIGKILL; in every other run it returns at once.
#[test]
fn the_killed_owners_child_writes_its_checkpoint() {
    if !exact_child::is_child(CHILD) {
        return;
    }
    exact_child::report(&exact_child::entered(CHILD));
    let (mut lock, env) = bound();
    let authority = crate::soak::tenure_authority(&mut lock);
    let arena = arena_on(TestPlatform::linux());
    let mut rig = Spdk {
        lock: &lock,
        env: &env,
        arena: &arena,
        registration: None,
        fault: Fault::ProcessDeath,
    };
    before(&mut rig, authority);
    unreachable!("the killed owner's fault parks until the parent's SIGKILL");
}
