use std::num::NonZeroU8;
use std::time::Duration;

use crate::soak::{Closed, Ended, Inconclusive, Soak, SoakConfig, SoakFailure, content, key};
use crate::storage::owner_fixture::{
    Device, QuiesceMode, SESSION, SimControl, SimDisk, TestPlatform, arena_on,
    heap_storage_limited_on, heap_storage_on, last_read, poison_maintenance, poison_shard,
    set_clock, write_tokens,
};
use crate::storage::{
    BeginError, BufferArena, InvalidateError, LookupError, ReadRefusal, RefusalReason, Storage,
    SubmitRefusal, WorkBudget,
};

const CONFIG: SoakConfig = SoakConfig {
    seed: 0x5EED,
    keys: NonZeroU8::new(16).unwrap(),
    body_cap: 40_000,
    capacity: 8,
    pressure: 2,
    cut_every: 8,
    patience: Duration::from_secs(10),
};

type SimSoak<'s, 'a> = Soak<'s, 'a, TestPlatform, SimDisk, Vec<u8>>;

fn soak<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    config: SoakConfig,
) -> (SimSoak<'s, 'a>, SimControl) {
    let Device { volume, control } = Device::new(storage, arena);
    let reader = storage.register().unwrap();
    let mut soak = Soak::new(storage, volume, reader, config, Vec::new());
    soak.device = Some(control.clone());
    (soak, control)
}

fn fixture() -> (Storage<TestPlatform>, BufferArena<TestPlatform>) {
    (
        heap_storage_on(512 << 10, 64 << 10),
        arena_on(TestPlatform::heap(4096), 16, 8),
    )
}

/// The payload's first byte, past the fixture's metadata prefix.
const PAYLOAD_START: u64 = crate::storage::TEST_METADATA_UNITS * crate::storage::IO_UNIT as u64;

fn lines(receipt: &[u8]) -> Vec<String> {
    let text = String::from_utf8(receipt.to_vec()).unwrap();
    for line in text.lines() {
        assert!(
            line.starts_with("{\"envelope\": {\"version\": 1, \"section\": \"soak\"}"),
            "{line}"
        );
    }
    text.lines().map(str::to_owned).collect()
}

fn run(soak: &mut SimSoak<'_, '_>, steps: usize) -> usize {
    let mut most = 0;
    for _ in 0..steps {
        let _ = soak.step();
        most = most.max(soak.unsettled());
        assert!(
            soak.unsettled() <= CONFIG.capacity,
            "the ledger stays bounded"
        );
        assert_eq!(soak.failure(), None);
    }
    most
}

fn hold_a_read(soak: &mut SimSoak<'_, '_>, control: &SimControl) -> crate::storage::CommandToken {
    for _ in 0..10_000 {
        let before = last_read(control);
        let _ = soak.step();
        if let Some(token) = last_read(control).filter(|token| Some(*token) != before)
            && control.try_hold(token).is_ok()
        {
            return token;
        }
    }
    panic!("the soak issued no read to hold");
}

fn lifecycle(ended: &Ended<'_, '_, TestPlatform, SimDisk, Vec<u8>>) -> String {
    lines(&ended.receipt).last().unwrap().clone()
}

/// A soak attached to a volume whose root slots both decode invalid formats it, takes each `Bootstrapping` refusal it meets while slot B's RESET write is held as a transient one, and fills once both RESET roots persist.
#[test]
fn a_soak_formats_its_disposable_volume_and_retries_fills_through_the_bootstrap() {
    let (storage, arena) = fixture();
    let (disk, control) = crate::storage::owner_fixture::device_with(7, 16384);
    let volume = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        crate::storage::owner_fixture::DEPTH,
        crate::storage::owner_fixture::TICK,
        &mut crate::storage::EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    let reader = storage.register().unwrap();
    let mut soak = Soak::new(&storage, volume, reader, CONFIG, Vec::new());
    soak.device = Some(control.clone());
    assert_eq!(
        soak.metadata_outcome(),
        crate::storage::MetadataOutcome::Bootstrapping
    );
    // Slot B's RESET write is held, so every fill the soak draws meanwhile meets `Bootstrapping`.
    let mut held = None;
    for _ in 0..100 {
        let _ = soak.step();
        assert_eq!(soak.failure(), None);
        if held.is_none()
            && let Some(token) = write_tokens(&control).get(1).copied()
        {
            control.hold(token);
            held = Some(token);
        }
    }
    let held = held.expect("slot B's RESET write");
    assert_eq!(
        soak.metadata_outcome(),
        crate::storage::MetadataOutcome::Bootstrapping
    );
    assert_eq!(
        crate::storage::owner_fixture::writes(&control),
        2,
        "no fill wrote during the bootstrap"
    );
    control.release(held);
    run(&mut soak, 200);
    assert_eq!(
        soak.metadata_outcome(),
        crate::storage::MetadataOutcome::Open
    );
    assert!(
        crate::storage::owner_fixture::writes(&control) > 2,
        "fills wrote past the two RESET roots"
    );
}

/// A metadata write whose retries exhaust fails the soak in the step whose poll applied the last `Failed` terminal, so a run that ends on that step reports `MetadataFailed` as its first recorded failure.
#[test]
fn a_soak_fails_in_the_step_whose_poll_recorded_metadata_failed() {
    let (storage, arena) = fixture();
    let (disk, control) = crate::storage::owner_fixture::device_with(7, 16384);
    let authority = crate::storage::ServingAuthority::fixture();
    let tenure = authority.session().get();
    let volume = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        crate::storage::owner_fixture::DEPTH,
        crate::storage::owner_fixture::TICK,
        &mut crate::storage::EngineBudget::new(1 << 24),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    let reader = storage.register().unwrap();
    let mut soak = Soak::new(&storage, volume, reader, CONFIG, Vec::new());
    soak.device = Some(control.clone());
    let mut faulted = 0;
    for _ in 0..100 {
        let _ = soak.step();
        for token in write_tokens(&control).into_iter().skip(faulted) {
            control.fault(
                token,
                crate::storage::owner_fixture::Fault::Status(crate::storage::DeviceStatus::Kernel(
                    -5,
                )),
            );
            faulted += 1;
        }
        if soak.metadata_outcome() == crate::storage::MetadataOutcome::MetadataFailed {
            assert_eq!(
                soak.failure(),
                Some(SoakFailure::Metadata {
                    outcome: crate::storage::MetadataOutcome::MetadataFailed
                }),
                "the step that applied the failing terminal records it"
            );
            assert!(!soak.witnesses().served, "the bootstrap never served");
            let ended = soak.close();
            assert_eq!(
                ended.failure,
                Some(SoakFailure::Metadata {
                    outcome: crate::storage::MetadataOutcome::MetadataFailed
                }),
                "a bootstrap failure stands through a never-serving close"
            );
            let line = lifecycle(&ended);
            assert!(line.contains("MetadataFailed"), "{line}");
            assert!(line.contains("\"session\": 0,"), "{line}");
            assert!(
                line.contains(&format!("\"tenure_session\": {tenure},")),
                "the refused bootstrap's receipt names the session it held: {line}"
            );
            return;
        }
    }
    panic!("the faulted RESET writes never exhausted their retries");
}

#[test]
fn a_soak_whose_authority_never_serves_ends_never_serving() {
    use crate::storage::gate_fixture::{arena_with, attach_reserving};
    let (storage, _) = fixture();
    let arena = arena_with(16, 8);
    let (volume, control, _registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture_standby(),
    );
    let reader = storage.register().unwrap();
    let mut soak = Soak::new(&storage, volume, reader, CONFIG, Vec::new());
    soak.device = Some(control.clone());
    for _ in 0..16 {
        let _ = soak.step();
        soak.poll();
        assert_eq!(soak.failure(), None);
    }
    let ended = soak.close();
    assert_eq!(ended.failure, Some(SoakFailure::NeverServing));
    assert!(
        lines(&ended.receipt)
            .last()
            .is_some_and(|line| line.contains("NeverServing")),
        "the lifecycle line names the failure"
    );
}

#[test]
fn a_no_fault_soak_reads_exact_bytes_across_many_bounded_windows_and_drains() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    let most = run(&mut soak, 2_000);
    assert!(soak.windows() >= 20, "{} windows", soak.windows());
    assert!(most > 0, "work stayed live between settlements");
    let witnesses = soak.witnesses();
    assert!(
        witnesses.queue_full && witnesses.near_capacity && witnesses.healed,
        "{witnesses:?}"
    );
    let windows = soak.windows();
    let ended = soak.close();
    assert_eq!(ended.failure, None);
    assert!(matches!(ended.closed, Closed::Drained(_)));
    let receipt = lines(&ended.receipt);
    assert!(
        receipt.len() as u64 == windows + 1 || receipt.len() as u64 == windows + 2,
        "one line per cut, the window in progress included, and the lifecycle: {} lines, {windows} windows",
        receipt.len()
    );
    assert!(
        receipt
            .last()
            .unwrap()
            .contains(&format!("\"windows\": {}", receipt.len() - 1)),
        "the lifecycle counts every cut: {}",
        receipt.last().unwrap()
    );
    let line = lifecycle(&ended);
    assert!(line.contains("\"lifecycle\": \"drained\""), "{line}");
    assert!(
        line.contains(&format!(
            "\"session\": {SESSION}, \"tenure_session\": {SESSION},"
        )),
        "the lifecycle line names the volume's session: {line}"
    );
}

#[test]
fn a_read_the_device_holds_stays_in_the_ledger_across_cuts_until_its_terminal() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    run(&mut soak, 200);
    let held = hold_a_read(&mut soak, &control);
    for _ in 0..2_000 {
        if soak.reads.len() == 1 {
            break;
        }
        soak.poll();
    }
    assert_eq!(soak.reads.len(), 1, "every read but the held one settled");
    let held_id = soak.reads[0].id;
    let mut carried = soak.unresolved();
    let windows = soak.windows();
    for _ in 0..10_000 {
        if soak.windows() >= windows + 3 {
            break;
        }
        let window = soak.windows();
        let _ = soak.step();
        if soak.windows() != window {
            let unresolved = soak.unresolved();
            carried.retain(|id| unresolved.contains(id));
        }
    }
    assert!(
        soak.windows() >= windows + 3 && carried.contains(&held_id),
        "the held read stays unresolved across every cut: {carried:?}"
    );
    assert!(soak.witnesses().held_read);
    control.release(held);
    run(&mut soak, 200);
    assert!(
        !soak.unresolved().contains(&held_id),
        "its terminal settled it"
    );
    let ended = soak.close();
    assert_eq!(ended.failure, None);
    let id = held_id.to_string();
    let named = lines(&ended.receipt)
        .iter()
        .filter(|line| {
            line.split("\"unresolved\": [").nth(1).is_some_and(|rest| {
                rest.split(']')
                    .next()
                    .unwrap()
                    .split(", ")
                    .any(|unresolved| unresolved == id)
            })
        })
        .count();
    assert!(named >= 3, "each cut while the read was held names it");
    assert!(matches!(ended.closed, Closed::Drained(_)));
}

#[test]
fn an_incorrect_or_short_read_fails_the_byte_check() {
    for (generation, len) in [(1, 0), (0, 1)] {
        let (storage, arena) = fixture();
        let (mut soak, _control) = soak(&storage, &arena, CONFIG);
        for _ in 0..2_000 {
            for n in 0..CONFIG.keys.get() {
                soak.misremember(n, generation, len);
            }
            let _ = soak.step();
            if soak.failure().is_some() {
                break;
            }
        }
        assert!(
            matches!(soak.failure(), Some(SoakFailure::Bytes { .. })),
            "{generation} {len}: {:?}",
            soak.failure()
        );
    }
}

#[test]
fn a_lease_held_outside_the_ledger_fails_the_credit_check() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    let mut other = storage.register().unwrap();
    let mut leaked = None;
    for _ in 0..2_000 {
        let _ = soak.step();
        if leaked.is_none() {
            leaked = (0..CONFIG.keys.get())
                .find_map(|n| other.lookup(&key(n), 4, &mut WorkBudget::new(1 << 16)).ok());
        }
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(leaked.is_some(), "a published key was leased");
    assert!(
        matches!(soak.failure(), Some(SoakFailure::Credits { .. })),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_full_ledger_refuses_the_next_operation_as_inconclusive() {
    let (storage, arena) = fixture();
    let config = SoakConfig {
        capacity: 1,
        pressure: 1,
        ..CONFIG
    };
    let (mut soak, control) = soak(&storage, &arena, config);
    hold_a_read(&mut soak, &control);
    let windows = soak.windows();
    let refused = (0..2_000).find_map(|_| soak.step().err());
    assert_eq!(refused, Some(Inconclusive::Ledger));
    assert_eq!(soak.windows(), windows + 1, "the refusal cut the window");
    assert_eq!(soak.unsettled(), 1, "the refusal dropped nothing");
}

#[test]
fn a_close_whose_stop_stays_unproven_retains_custody_in_its_receipt() {
    let (storage, arena) = fixture();
    let config = SoakConfig {
        patience: Duration::from_millis(200),
        ..CONFIG
    };
    let (mut soak, control) = soak(&storage, &arena, config);
    run(&mut soak, 200);
    hold_a_read(&mut soak, &control);
    control.set_quiesce(QuiesceMode::Unproven);
    let ended = soak.close();
    assert!(matches!(ended.closed, Closed::Retained(_)));
    let line = lifecycle(&ended);
    assert!(line.contains("\"lifecycle\": \"retained\""), "{line}");
    let abandoned: u32 = line
        .split("\"commands_abandoned\": ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        abandoned >= 1,
        "the cancelled read's command stays with the device: {line}"
    );
}

#[test]
fn the_receipt_names_the_clock_trust_and_the_absent_pairs() {
    use crate::storage::portable::scripted::ScriptedClock;
    for trusted in [true, false] {
        let (storage, arena) = fixture();
        let clock = if trusted {
            ScriptedClock::trusted()
        } else {
            ScriptedClock::untrusted()
        };
        let Device { volume, control } = Device::clocked(&storage, &arena, clock);
        let reader = storage.register().unwrap();
        let mut soak = Soak::new(&storage, volume, reader, CONFIG, Vec::new());
        soak.device = Some(control.clone());
        run(&mut soak, 200);
        let line = lifecycle(&soak.close());
        let absent: u64 = line
            .split("\"absent_expiry\": ")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .unwrap_or_else(|| panic!("the receipt names no absent pairs: {line}"))
            .parse()
            .unwrap();
        if trusted {
            assert!(
                line.contains("\"clock_trust\": \"Some(Trusted)\""),
                "{line}"
            );
            assert_eq!(absent, 0, "{line}");
        } else {
            assert!(
                line.contains("\"clock_trust\": \"Some(Untrusted(NoSnapshot))\""),
                "{line}"
            );
            assert!(
                absent > 0,
                "the soak published under an untrusted clock: {line}"
            );
        }
    }
}

#[test]
fn content_is_a_function_of_key_generation_and_length() {
    assert_eq!(content(1, 2, 64), content(1, 2, 64));
    assert_ne!(content(1, 2, 64), content(1, 3, 64));
    assert_ne!(content(1, 2, 64), content(2, 2, 64));
    assert_eq!(content(1, 2, 64)[..10], content(1, 2, 10)[..]);
}

#[test]
#[ignore = "needs a start that issues the soak's PreBoundary serving authority a token, as a restart's own-holder Report does, so its attach gate runs and crosses the fencing boundary, a bound disposable EBS volume that no qualification profile attaches in the same boot, a process-owned 0700 state directory outside /run containing 0600 host.key, assignment and authority files, IMDSv2, and KESTRIKE_MAPPINGS, KESTRIKE_N_REG, KESTRIKE_N_RESV, KESTRIKE_T_REPORT, KESTRIKE_T_PA, KESTRIKE_N_RETRY, KESTRIKE_SERVING_WINDOW_US, KESTRIKE_REPORT_PERIOD_US and KESTRIKE_CLOCK_ERROR_US"]
fn the_soak_smoke_drains_on_the_bound_volume() {
    let mappings = std::env::var("KESTRIKE_MAPPINGS").unwrap();
    let seconds: u64 =
        std::env::var("KESTRIKE_SOAK_SECONDS").map_or(120, |text| text.parse().unwrap());
    assert!(seconds > 0, "a zero-second soak exercises nothing");
    let bound = crate::soak::BoundConfig {
        run: Duration::from_secs(seconds),
        allow_no_iommu: true,
        ..crate::soak::SMOKE_BOUND
    };
    let failure = crate::soak::soak_bound(
        std::path::Path::new(&mappings),
        crate::soak::SMOKE,
        bound,
        |_| Ok(std::io::stderr()),
    )
    .unwrap();
    assert_eq!(failure, None);
}

#[test]
fn a_read_the_ledger_lost_fails_as_untracked() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    let held = hold_a_read(&mut soak, &control);
    soak.reads.pop();
    control.release(held);
    for _ in 0..2_000 {
        soak.poll();
        if soak.failure().is_some() {
            break;
        }
    }
    assert_eq!(soak.failure(), Some(SoakFailure::Untracked));
}

#[test]
fn a_close_during_a_fill_s_writes_aborts_the_fill_and_keeps_or_drains_its_commands() {
    for released in [false, true] {
        let (storage, arena) = fixture();
        let config = SoakConfig {
            patience: Duration::from_millis(200),
            ..CONFIG
        };
        let (mut soak, control) = soak(&storage, &arena, config);
        run(&mut soak, 100);
        let mut seen: std::collections::HashSet<_> =
            crate::storage::owner_fixture::writes_from(&control, PAYLOAD_START)
                .into_iter()
                .collect();
        let held = (0..10_000)
            .find_map(|_| {
                let _ = soak.step();
                let fresh: Vec<_> =
                    crate::storage::owner_fixture::writes_from(&control, PAYLOAD_START)
                        .into_iter()
                        .filter(|token| seen.insert(*token))
                        .collect();
                fresh
                    .into_iter()
                    .rev()
                    .find(|&token| control.try_hold(token).is_ok())
            })
            .expect("a fill's write reached the device");
        if released {
            control.release(held);
        }
        let ended = soak.close();
        let line = lifecycle(&ended);
        assert!(line.contains("\"aborted_fill\": true"), "{line}");
        assert_eq!(
            matches!(ended.closed, Closed::Drained(_)),
            released,
            "{line}"
        );
    }
}

#[test]
fn a_fill_whose_final_submit_is_refused_retries_it_and_publishes() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    let full = SubmitRefusal {
        reason: RefusalReason::QueueFull,
        code: None,
    };
    for step in 0..600 {
        if step % 3 == 0 {
            let _ = control.try_refuse_next(full);
        }
        let _ = soak.step();
        assert_eq!(soak.failure(), None);
    }
    let open = soak.unresolved();
    for _ in 0..2_000 {
        let _ = soak.step();
    }
    let unresolved = soak.unresolved();
    assert!(
        open.iter().all(|id| !unresolved.contains(id)),
        "every fill, lease and read open after the refusals settled: {open:?} still {unresolved:?}"
    );
    assert_eq!(soak.failure(), None);
}

#[test]
fn a_pressure_after_the_queue_full_witness_still_issues_reads() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    for _ in 0..2_000 {
        if soak.witnesses().queue_full {
            break;
        }
        let _ = soak.step();
    }
    assert!(soak.witnesses().queue_full, "the workload filled the queue");
    for _ in 0..2_000 {
        if soak.reads.is_empty() {
            break;
        }
        soak.poll();
    }
    assert!(soak.reads.is_empty(), "every live read settled");
    let pressed = (0..CONFIG.keys.get()).any(|n| {
        let before = soak.reads.len();
        soak.pressure(n).is_ok() && soak.reads.len() > before
    });
    assert!(pressed, "a pressure on a published key issued reads");
    assert_eq!(soak.failure(), None);
}

#[test]
fn a_terminal_fill_start_refusal_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    storage.close();
    for _ in 0..200 {
        let _ = soak.step();
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(
            soak.failure(),
            Some(SoakFailure::Begin {
                error: BeginError::Closed,
                ..
            })
        ),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_read_the_lost_volume_refuses_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    run(&mut soak, 300);
    for _ in 0..2_000 {
        if soak.reads.is_empty() {
            break;
        }
        soak.poll();
    }
    assert!(soak.reads.is_empty(), "every live read settled");
    assert_eq!(soak.failure(), None);
    control.set_gone();
    for n in 0..CONFIG.keys.get() {
        let _ = soak.pressure(n);
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(
            soak.failure(),
            Some(SoakFailure::Refused {
                refusal: ReadRefusal::Lost,
                ..
            })
        ),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_fill_whose_publication_fails_for_a_lasting_cause_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    let _ = soak.invalidate(0);
    assert_eq!(soak.failure(), None);
    soak.fill(0).unwrap();
    assert_eq!(soak.unsettled(), 1, "key 0's fill is open");
    for _ in 0..2_000 {
        // The expiry sweep takes the first sample; the publication's own
        // sample is the second.
        set_clock(&storage, &[Some(1), None]);
        soak.poll();
        if soak.failure().is_some() {
            break;
        }
    }
    assert_eq!(soak.failure(), Some(SoakFailure::Fill { key: 0 }));
}

fn filled_alone(soak: &mut SimSoak<'_, '_>, n: u8) {
    soak.fill(n).unwrap();
    for _ in 0..2_000 {
        if soak.unsettled() == 0 {
            break;
        }
        soak.poll();
    }
    assert_eq!((soak.unsettled(), soak.failure()), (0, None));
}

#[test]
fn a_full_index_at_reservation_is_pressure_the_soak_retries() {
    let storage = heap_storage_limited_on(512 << 10, 64 << 10, 1, 16);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    filled_alone(&mut soak, 0);
    let mut other = storage.register().unwrap();
    let visible = other.lookup(&key(0), 4, &mut WorkBudget::new(1 << 16));
    assert!(visible.is_ok(), "key 0 fills the one-key index");
    drop(visible);
    soak.fill(1).unwrap();
    assert_eq!(soak.failure(), None, "a full index is retried");
    assert_eq!(soak.unsettled(), 0);
    assert!(soak.witnesses().near_capacity);
}

#[test]
fn a_full_lease_limit_at_reservation_is_pressure_the_soak_retries() {
    // A fill reserves two credits; the soak's lease and another reader's
    // lease then hold both, so the next fill's reservation refuses.
    let storage = heap_storage_limited_on(512 << 10, 64 << 10, 8, 2);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    filled_alone(&mut soak, 0);
    let mut other = storage.register().unwrap();
    let held = other
        .lookup(&key(0), 4, &mut WorkBudget::new(1 << 16))
        .unwrap();
    soak.fill(1).unwrap();
    assert_eq!(soak.failure(), None, "a full lease limit is retried");
    assert_eq!(soak.unsettled(), 0);
    assert!(!soak.witnesses().near_capacity);
    drop(held);
}

#[test]
fn a_retired_backlog_at_reservation_is_pressure_the_soak_retries_without_a_capacity_witness() {
    let storage = heap_storage_limited_on(512 << 10, 64 << 10, 8, 16);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    let mut other = storage.register().unwrap();
    let mut held = Vec::new();
    let mut n = 0;
    loop {
        let domain = storage.domain_report().unwrap();
        if domain.retired_units >= domain.retired_limit {
            break;
        }
        filled_alone(&mut soak, n);
        held.push(
            other
                .lookup(&key(n), 4, &mut WorkBudget::new(1 << 16))
                .unwrap(),
        );
        soak.invalidate(n).unwrap();
        assert_eq!(soak.failure(), None);
        n += 1;
    }
    let domain = storage.domain_report().unwrap();
    assert!(domain.free_units > domain.low_units, "{domain:?}");
    assert!(!soak.witnesses().near_capacity);
    soak.fill(n).unwrap();
    assert_eq!(soak.failure(), None, "retired pressure is retried");
    assert_eq!(soak.unsettled(), 0);
    assert!(!soak.witnesses().near_capacity);
    drop(held);
}

#[test]
fn a_window_with_nothing_settling_still_cuts_and_carries_its_fill() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    control.set_halted(true);
    for _ in 0..20_000 {
        let _ = soak.step();
    }
    assert_eq!(soak.failure(), None, "the patience has not expired");
    assert!(
        soak.windows() >= 1,
        "steps alone cut a window; the tape stays bounded"
    );
    assert_eq!(soak.unsettled(), 1, "the pending fill carries across cuts");
}

#[test]
fn a_fill_whose_receive_the_lost_volume_refuses_fails_the_soak_at_once() {
    let (storage, arena) = fixture();
    let (mut soak, control) = soak(&storage, &arena, CONFIG);
    control.set_gone();
    for _ in 0..2_000 {
        let _ = soak.step();
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(soak.failure(), Some(SoakFailure::Fill { .. })),
        "{:?}",
        soak.failure()
    );
}

/// Publishes objects, then settles every fill and read.
fn settled_publications(soak: &mut SimSoak<'_, '_>) {
    run(soak, 300);
    for _ in 0..2_000 {
        if soak.unsettled() == 0 {
            break;
        }
        soak.poll();
    }
    assert_eq!(soak.unsettled(), 0, "every fill and read settled");
}

#[test]
fn an_invalidation_the_closed_storage_refuses_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    storage.close();
    for n in 0..CONFIG.keys.get() {
        let _ = soak.invalidate(n);
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(
            soak.failure(),
            Some(SoakFailure::Invalidate {
                error: InvalidateError::Closed,
                ..
            })
        ),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_lookup_without_a_clock_sample_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    set_clock(&storage, &[None]);
    for n in 0..CONFIG.keys.get() {
        let _ = soak.pressure(n);
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(
            soak.failure(),
            Some(SoakFailure::Lookup {
                error: LookupError::ClockUnavailable,
                ..
            })
        ),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_close_after_steps_without_a_cut_records_the_partial_window() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    let _ = soak.step();
    assert_eq!(soak.windows(), 0, "one step settles below the cut");
    let ended = soak.close();
    let receipt = lines(&ended.receipt);
    assert_eq!(
        receipt.len(),
        2,
        "the partial window's cut, then the lifecycle: {receipt:?}"
    );
    assert!(receipt[0].contains("\"cut\": 0"), "{}", receipt[0]);
    assert!(receipt[1].contains("\"windows\": 1"), "{}", receipt[1]);
}

#[test]
fn an_interrupted_soak_fails_as_interrupted_and_says_so_in_its_receipt() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    run(&mut soak, 50);
    soak.interrupt();
    let ended = soak.close();
    assert_eq!(ended.failure, Some(SoakFailure::Interrupted));
    assert!(lifecycle(&ended).contains("Interrupted"));
}

#[test]
fn an_inconclusive_step_records_the_failure_before_the_lifecycle_line() {
    let (storage, arena) = fixture();
    let config = SoakConfig {
        capacity: 1,
        pressure: 1,
        ..CONFIG
    };
    let (mut soak, control) = soak(&storage, &arena, config);
    let held = hold_a_read(&mut soak, &control);
    let refused = (0..2_000).find_map(|_| soak.step().err());
    assert_eq!(refused, Some(Inconclusive::Ledger));
    assert_eq!(soak.failure(), Some(SoakFailure::Inconclusive));
    control.release(held);
    let ended = soak.close();
    assert!(
        lifecycle(&ended).contains("Inconclusive"),
        "{}",
        lifecycle(&ended)
    );
}

#[test]
fn a_poisoned_gate_fails_the_soak_as_contention() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    poison_shard(&storage);
    for _ in 0..2_000 {
        let _ = soak.step();
        if soak.failure().is_some() {
            break;
        }
    }
    assert!(
        matches!(
            soak.failure(),
            Some(
                SoakFailure::Begin {
                    error: BeginError::Contended,
                    ..
                } | SoakFailure::Lookup {
                    error: LookupError::Contended,
                    ..
                } | SoakFailure::Invalidate {
                    error: InvalidateError::Contended,
                    ..
                } | SoakFailure::Maintenance { .. }
            )
        ),
        "{:?}",
        soak.failure()
    );
}

#[test]
fn a_poisoned_maintenance_gate_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    poison_maintenance(&storage);
    soak.poll();
    assert_eq!(
        soak.failure(),
        Some(SoakFailure::Maintenance {
            contended: 1,
            clock_unavailable: false,
        })
    );
}

#[test]
fn maintenance_without_a_clock_sample_fails_the_soak() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    set_clock(&storage, &[None]);
    soak.poll();
    assert!(
        matches!(
            soak.failure(),
            Some(SoakFailure::Maintenance {
                clock_unavailable: true,
                ..
            })
        ),
        "{:?}",
        soak.failure()
    );
}

/// What one run of [`advanced_past_a_refusal`] observed.
struct Refused {
    failure: Option<SoakFailure>,
    /// The feed position just before and just after the refused invalidation.
    feed: (u64, u64),
}

/// Settles a run, then invalidates published keys: the first under a held shard gate, which refuses it `Contended`, and the rest freely.
fn advanced_past_a_refusal() -> Refused {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    let published: Vec<u8> = (0..CONFIG.keys.get())
        .filter(|&n| soak.is_published(n))
        .collect();
    assert!(published.len() >= 2, "{published:?}");
    let before = soak.feed();
    {
        let _held = crate::storage::owner_fixture::hold_shard(&storage);
        soak.invalidate(published[0]).unwrap();
    }
    let after = soak.feed();
    assert!(soak.is_published(published[0]));
    for &n in &published[1..] {
        soak.invalidate(n).unwrap();
    }
    soak.poll();
    Refused {
        failure: soak.failure(),
        feed: (before, after),
    }
}

/// The soak fails a `Contended` invalidation, which its one thread cannot cause, and gives it no feed position.
#[test]
fn a_contended_invalidation_takes_no_feed_position() {
    let refused = advanced_past_a_refusal();
    assert!(
        matches!(
            refused.failure,
            Some(SoakFailure::Invalidate {
                error: InvalidateError::Contended,
                ..
            })
        ),
        "{:?}",
        refused.failure
    );
    assert_eq!(refused.feed.0, refused.feed.1);
}

/// A key the storage removed behind the soak's back, as an eviction does, is invalidated with `removed: None`, which excludes nothing; after the volume settled, the close has no durable exclusion to wait for and ends with no failure.
#[test]
fn a_close_after_an_absent_key_s_invalidation_ends_with_no_failure() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    let n = (0..CONFIG.keys.get())
        .find(|&n| soak.is_published(n))
        .expect("a published key");
    let removed = storage
        .invalidate(&key(n), 4, &mut WorkBudget::new(1 << 16))
        .unwrap();
    assert!(removed.removed.is_some(), "the key was published");
    for _ in 0..200 {
        soak.poll();
    }
    assert!(
        soak.is_published(n),
        "the soak still records the key published"
    );
    soak.invalidate(n).unwrap();
    assert!(!soak.is_published(n));
    let ended = soak.close();
    assert!(
        lifecycle(&ended).contains("\"failure\": \"None\""),
        "{}",
        lifecycle(&ended)
    );
}

/// An invalidation refused `BudgetExhausted` keeps its key in the workload and takes no feed position, and the run continues without a failure.
#[test]
fn an_exhausted_invalidation_budget_takes_no_feed_position() {
    let (storage, arena) = fixture();
    let (mut soak, _control) = soak(&storage, &arena, CONFIG);
    settled_publications(&mut soak);
    let n = (0..CONFIG.keys.get())
        .find(|&n| soak.is_published(n))
        .expect("a published key");
    let before = soak.feed();
    soak.invalidation_budget = Some(0);
    soak.invalidate(n).unwrap();
    assert_eq!(soak.feed(), before);
    assert!(soak.is_published(n));
    assert_eq!(soak.failure(), None);
    soak.invalidation_budget = None;
    soak.invalidate(n).unwrap();
    assert_eq!(soak.feed(), before + 1);
    assert!(!soak.is_published(n));
}

#[test]
fn a_volume_whose_roots_record_another_layout_names_the_root_slot_wipe() {
    use crate::storage::MetadataOutcome;
    let mismatch = SoakFailure::Metadata {
        outcome: MetadataOutcome::FormatMismatch,
    };
    let remedy = mismatch
        .remedy()
        .expect("a format mismatch names its remedy");
    assert!(remedy.contains("root slots"), "{remedy}");
    assert!(remedy.contains("discards its recovery state"), "{remedy}");
    assert!(remedy.contains("kestrike-bind --release"), "{remedy}");
    assert!(remedy.contains("store that last attached"), "{remedy}");
    assert!(remedy.contains("is replaced"), "{remedy}");
    let stale = SoakFailure::Metadata {
        outcome: MetadataOutcome::StaleSession,
    }
    .remedy()
    .expect("a stale session names its remedy");
    assert!(stale.contains("soak-store"), "{stale}");
    assert!(stale.contains("restore the store"), "{stale}");
    assert!(stale.contains("is replaced"), "{stale}");
    assert!(stale.contains("new state directory"), "{stale}");
    for failure in [
        SoakFailure::Metadata {
            outcome: MetadataOutcome::MetadataFailed,
        },
        SoakFailure::Untracked,
        SoakFailure::Receipt,
    ] {
        assert_eq!(failure.remedy(), None, "{failure:?}");
    }
}
