//! Reservation encoding, extended Report evidence and command custody over the scripted Native boundary.

use super::disk::SpdkDisk;
use super::disk_tests::{Call, SCRIPT, Scripted, limits};
use super::native::{Native, Spdk};
use crate::failover::evidence::{NotSole, Pair, Registrant, ReservationType};
use crate::failover::identity::{Exhid, Key};
use crate::storage::test_platform::TestPlatform;
use crate::storage::volume_fixture::{JUMP, ServingTime};
use crate::storage::{
    BufferArena, BufferConfig, CommandTable, DeviceRange, EngineBudget, Failure, HugepageSize,
    NodeMask, PollReport, PoolKind, PoolSpec, QuiesceProgress, Quiesced, Refusal, RefusalReason,
    ReportError, ReservationCommand, ReservationLimits, ReservationLimitsError, Terminal,
    parse_extended_report, report_exhid,
};

fn bounds() -> ReservationLimits {
    ReservationLimits::new(3, 2, 10, 20).unwrap()
}

pub(crate) fn scripted_reserving(
    address: &str,
    depth: u32,
    limits: ReservationLimits,
) -> SpdkDisk<'static, Scripted> {
    let mut disk = SpdkDisk::<Scripted>::scripted(address, super::disk_tests::limits(depth));
    disk.set_reservation_limits(limits);
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
    disk
}
/// Runs a withdrawal on a scripted disk holding `authority`: an accepted Register of the authority's own key, then quiesce, stop and detach.
pub(crate) fn withdraw_with(authority: crate::bind::AttachAuthority) {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink, DmaRange};
    SCRIPT.take();
    let pair = authority.pair();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:authority-withdraw",
        limits(8),
        &mut registration,
    );
    disk.set_reservation_limits(bounds());
    disk.set_authority(authority);
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(buffer.range(4096).unwrap());
    let command = ReservationCommand::Register { new: pair.key };
    command.encode(&mut buffer.bytes_mut()[..16]);
    let memory = DmaRange::new(buffer.range(4096).unwrap().addr(), buffer.offset(), 16);
    // SAFETY: buffer custody remains with the command until its certified terminal below.
    unsafe { disk.submit_reservation(CommandToken::from_raw(1), command, memory) }.unwrap();
    let mut out = Vec::with_capacity(1);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
    assert_eq!(out.len(), 1);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}
fn key(n: u64) -> Key {
    Key::decode((n << 32) | n).unwrap()
}

/// A lineage preempt for `own` resolved from a Report in which `holder`, a recorded pair, holds the type-2
/// reservation beside `own`'s non-holding registration.
fn lineage_preempt(own: Pair, holder: Pair) -> crate::storage::LineagePreempt {
    let entries = [
        Registrant {
            cntlid: 1,
            holder: true,
            pair: holder,
        },
        Registrant {
            cntlid: 2,
            holder: false,
            pair: own,
        },
    ];
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl: 2,
        entries: &entries,
    };
    crate::storage::LineagePreempt::resolve(&report, &[holder], &[holder], own, &preempt_bounds())
        .unwrap()
}

/// An ended preempt for `own` of the key of entry 3, which a volume record numbered up to 5 ties to no live attach,
/// resolved from a Report in which `own` holds alone beside a registrant under that key.
fn ended_preempt(own: Pair) -> crate::storage::EndedPreempt {
    let ended = crate::failover::records::attachment_key(3).unwrap();
    let entries = [
        Registrant {
            cntlid: 1,
            holder: true,
            pair: own,
        },
        Registrant {
            cntlid: 2,
            holder: false,
            pair: Pair {
                exhid: Exhid::new([2; 16]).unwrap(),
                key: ended,
            },
        },
    ];
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl: 2,
        entries: &entries,
    };
    let volume = crate::failover::records::VolumeRecord {
        next: 5,
        ..crate::failover::poll_tests::volume(
            crate::failover::records::VolumeState::Active,
            crate::failover::records::Host::new(7).unwrap(),
        )
    };
    crate::storage::EndedPreempt::resolve(&report, &volume, ended, own, &preempt_bounds()).unwrap()
}

/// The self preempt of `own`, built from a Report that shows `own` as the one holder.
pub(crate) fn self_preempt(own: Pair) -> crate::storage::SelfPreempt {
    let entries = [Registrant {
        cntlid: 0xFFFF,
        holder: true,
        pair: own,
    }];
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl: 1,
        entries: &entries,
    };
    crate::storage::SelfPreempt::from_report(&report, &preempt_bounds(), own).unwrap()
}
fn preempt_bounds() -> crate::failover::bounds::Bounds {
    crate::failover::bounds::Bounds::new(3, 1, 100, 10, 10, 0).unwrap()
}
/// The pair of `key` under the scripted driver's host ID.
fn scripted_pair(key: Key) -> Pair {
    Pair {
        key,
        ..dummy().pair
    }
}
fn dummy() -> Registrant {
    Registrant {
        cntlid: 0,
        holder: false,
        pair: Pair {
            exhid: Exhid::new([1; 16]).unwrap(),
            key: key(1),
        },
    }
}

fn arena() -> BufferArena<TestPlatform> {
    arena_with_len(4096)
}

fn arena_with_len(buffer_len: u32) -> BufferArena<TestPlatform> {
    let pools = [
        PoolKind::ReadResponse,
        PoolKind::ReceiveWrite,
        PoolKind::Maintenance,
        PoolKind::Reservation,
    ]
    .map(|kind| PoolSpec {
        kind,
        count: if kind == PoolKind::Reservation { 2 } else { 8 },
        buffer_len,
    });
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    BufferArena::initialize(
        &config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap()
}
fn table<'a>(
    arena: &'a BufferArena<TestPlatform>,
    name: &str,
) -> CommandTable<'a, SpdkDisk<'a, Scripted>> {
    SCRIPT.take();
    let mut disk = SpdkDisk::<Scripted>::scripted(name, limits(8));
    disk.set_reservation_limits(bounds());
    let probe = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(probe.range(4096).unwrap());
    drop(probe);
    CommandTable::new(disk, arena, 8, &mut EngineBudget::new(usize::MAX)).unwrap()
}
fn report(count: usize) -> Vec<u8> {
    let mut bytes = vec![0; 64 + 64 * count];
    bytes[4] = 2;
    bytes[5..7].copy_from_slice(&(count as u16).to_le_bytes());
    for n in 0..count {
        let entry = &mut bytes[64 + 64 * n..64 + 64 * (n + 1)];
        entry[..2].copy_from_slice(&(n as u16 + 10).to_le_bytes());
        entry[2] = u8::from(n == 0);
        entry[8..16].copy_from_slice(&key(n as u64 + 1).encode().to_le_bytes());
        entry[16..32].fill(n as u8 + 1);
    }
    bytes
}
fn conservation(
    table: &CommandTable<'_, SpdkDisk<'_, Scripted>>,
    arena: &BufferArena<TestPlatform>,
) {
    let r = table.report();
    assert_eq!(
        r.free_slots + r.pending + r.abandoned + r.retired,
        u32::from(r.depth)
    );
    let (storage, quarantined) = PoolKind::ALL.iter().fold((0, 0), |(s, q), kind| {
        let pool = arena.report(*kind);
        (s + pool.storage, q + pool.quarantined)
    });
    assert_eq!(r.pending + r.abandoned, storage + quarantined, "{r:?}");
    assert_eq!(r.abandoned, quarantined, "{r:?}");
}

#[test]
fn connect_options_replace_the_process_default_with_the_persisted_exhid() {
    let persisted = Exhid::new(*b"persisted-exhid!").unwrap();
    let mut opts = spdk_sys::spdk_nvme_ctrlr_opts::default();
    // SAFETY: the options structure is writable and the fixture represents a persisted identity.
    unsafe {
        Spdk::connect_options(&mut opts, persisted.bytes());
    }
    assert_eq!(opts.extended_host_id, *b"persisted-exhid!");
    assert_eq!(opts.opts_size, std::mem::size_of_val(&opts));
    assert_ne!(opts.num_io_queues, 0);
    assert_eq!(
        Exhid::new([0; 16]),
        Err(crate::failover::identity::IdentityError::ExhidZero)
    );
    assert!(super::disk_tests::calls().is_empty());
}

#[test]
fn owner_bounds_refuse_zero_insufficient_and_unrepresentable_values() {
    for (n, slots, tr, tp, expected) in [
        (0, 2, 1, 1, ReservationLimitsError::Registrants),
        (65536, 2, 1, 1, ReservationLimitsError::Registrants),
        (2, 1, 1, 1, ReservationLimitsError::Commands),
        (2, 2, 0, 1, ReservationLimitsError::Deadline),
        (2, 2, 1, 0, ReservationLimitsError::Deadline),
    ] {
        assert_eq!(ReservationLimits::new(n, slots, tr, tp), Err(expected));
    }
    assert_eq!(
        (
            bounds().registrants(),
            bounds().commands(),
            bounds().report_bytes(),
            bounds().report_timeout(),
            bounds().preempt_timeout()
        ),
        (3, 2, 256, 10, 20)
    );
}

#[test]
fn extended_reports_decode_zero_one_and_the_bound_with_exact_pairs() {
    for n in [0, 1, 3] {
        let mut entries = [dummy(); 3];
        let bytes = report(n);
        let parsed = parse_extended_report(&bytes, bounds(), 11, &mut entries).unwrap();
        assert_eq!(
            (parsed.submitted_at, parsed.regctl, parsed.rtype),
            (11, n as u32, ReservationType::ExclusiveAccess)
        );
        assert_eq!(parsed.entries.len(), n);
        for (index, entry) in parsed.entries.iter().enumerate() {
            assert_eq!(
                (
                    entry.cntlid,
                    entry.holder,
                    entry.pair.key,
                    entry.pair.exhid.bytes()
                ),
                (
                    index as u16 + 10,
                    index == 0,
                    key(index as u64 + 1),
                    [index as u8 + 1; 16]
                )
            );
        }
    }
}

#[test]
fn malformed_short_format_and_over_bound_reports_establish_no_evidence() {
    let mut entries = [dummy(); 3];
    let bytes = report(3);
    for end in 0..bytes.len() {
        assert_eq!(
            parse_extended_report(&bytes[..end], bounds(), 1, &mut entries),
            Err(ReportError::Truncated),
            "{end}"
        );
    }
    let mut duplicate = report(2);
    duplicate[136..144].copy_from_slice(&key(1).encode().to_le_bytes());
    refuses_a_duplicate_key(&duplicate);
    assert_eq!(
        parse_extended_report(&report(4), bounds(), 1, &mut entries),
        Err(ReportError::Inconclusive { regctl: 4 })
    );
    for width in [0, 8, 15, 17] {
        assert_eq!(report_exhid(&vec![1; width]), Err(ReportError::ExhidLength));
    }
    let mut legacy = vec![0; 256];
    legacy[4] = 2;
    legacy[5] = 1;
    legacy[32..40].copy_from_slice(&key(1).encode().to_le_bytes());
    legacy[40..48].fill(1);
    assert_eq!(
        parse_extended_report(&legacy, bounds(), 1, &mut entries),
        Err(ReportError::Identity(
            crate::failover::identity::IdentityError::Zero(crate::failover::identity::Field::Epoch)
        ))
    );
    let mut wrong_type = report(0);
    wrong_type[4] = 1;
    assert_eq!(
        parse_extended_report(&wrong_type, bounds(), 1, &mut entries),
        Err(ReportError::ReservationType(1))
    );
}

/// Asserts that the extended Report `bytes` establishes no evidence and refuses as a duplicate key.
fn refuses_a_duplicate_key(bytes: &[u8]) {
    let mut entries = [dummy(); 3];
    assert_eq!(
        parse_extended_report(bytes, bounds(), 1, &mut entries),
        Err(ReportError::DuplicateKey),
        "one key under two host identifiers establishes no evidence"
    );
}

/// Requiring `Ok(2)` establishes the two-entry precondition for the expected panic in `refuses_a_duplicate_key`.
#[test]
#[should_panic(expected = "one key under two host identifiers establishes no evidence")]
fn negative_control_a_report_without_the_duplicated_key_establishes_evidence() {
    let bytes = report(2);
    let mut entries = [dummy(); 3];
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 1, &mut entries).map(|report| report.entries.len()),
        Ok(2),
        "the planted Report decodes to its two entries"
    );
    refuses_a_duplicate_key(&bytes);
}

/// Each command encodes its exact CRKEY and PRKEY words, action and type: a self preempt names the own key twice, a
/// lineage preempt names the own key as CRKEY and the resolved holder's key as PRKEY under the same Preempt-and-Abort
/// action and type 2, an ended preempt names the own key as CRKEY and the ended key as PRKEY under Preempt (RACQA 1)
/// and type 2, and the Report carries the configured length.
#[test]
fn commands_encode_exact_keys_actions_and_extended_report_length() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reservation-encoding");
    let mut out = Vec::with_capacity(8);
    let commands = [
        ReservationCommand::Register { new: key(2) },
        ReservationCommand::Register { new: key(3) },
        ReservationCommand::Acquire { current: key(3) },
        ReservationCommand::PreemptAndAbort(self_preempt(scripted_pair(key(3)))),
        ReservationCommand::PreemptLineage(lineage_preempt(
            scripted_pair(key(3)),
            Pair {
                exhid: Exhid::new([2; 16]).unwrap(),
                key: key(2),
            },
        )),
        ReservationCommand::PreemptEnded(ended_preempt(scripted_pair(key(3)))),
        ReservationCommand::Report { not_before: 5 },
    ];
    for (ordinal, command) in commands.into_iter().enumerate() {
        let token = table.submit_reservation(command, ordinal as u64).unwrap();
        assert_eq!(table.poll(&mut out).delivered, 1);
        assert_eq!(out[0].token(), token);
        drop(out.pop());
        conservation(&table, &arena);
    }
    let seen = SCRIPT.with_borrow(|s| s.reservation_calls.clone());
    assert_eq!(seen.len(), commands.len());
    let pairs = [
        (0, key(2).encode()),
        (0, key(3).encode()),
        (key(3).encode(), 0),
        (key(3).encode(), key(3).encode()),
        (key(3).encode(), key(2).encode()),
        (
            key(3).encode(),
            crate::failover::records::attachment_key(3)
                .unwrap()
                .encode(),
        ),
        (0, 0),
    ];
    for (index, (call, action, argument, len, bytes)) in seen.into_iter().enumerate() {
        assert_eq!(
            (call, action, argument, len),
            [
                (Call::Register, 0, 0, 16),
                (Call::Register, 0, 0, 16),
                (Call::Acquire, 0, 2, 16),
                (Call::Acquire, 2, 2, 16),
                (Call::Acquire, 2, 2, 16),
                (Call::Acquire, 1, 2, 16),
                (Call::Report, 0, 0, 256)
            ][index]
        );
        assert_eq!(
            (
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u64::from_le_bytes(bytes[8..].try_into().unwrap())
            ),
            pairs[index]
        );
    }
    assert_eq!(arena.report(PoolKind::Reservation).free, 0);
}

/// Submits the first `commands` of six writes, two from each of the read, receive and maintenance pools in that order,
/// each accepted.
fn occupy<'a>(
    table: &mut CommandTable<'a, SpdkDisk<'a, Scripted>>,
    arena: &'a BufferArena<TestPlatform>,
    commands: usize,
) {
    let kinds = [
        PoolKind::ReadResponse,
        PoolKind::ReceiveWrite,
        PoolKind::Maintenance,
    ];
    for kind in kinds
        .into_iter()
        .flat_map(|kind| [kind, kind])
        .take(commands)
    {
        table
            .submit_write(
                arena.acquire(kind).unwrap(),
                DeviceRange::new(0, 4096).unwrap(),
            )
            .unwrap();
    }
}

fn data_submit_refusal<'a>(
    table: &mut CommandTable<'a, SpdkDisk<'a, Scripted>>,
    arena: &'a BufferArena<TestPlatform>,
) -> Option<Refusal> {
    table
        .submit_write(
            arena.acquire(PoolKind::ReceiveWrite).unwrap(),
            DeviceRange::new(0, 4096).unwrap(),
        )
        .err()
        .map(|rejected| rejected.refusal)
}

fn refuses_table_full(refusal: Option<Refusal>) {
    assert_eq!(
        refusal,
        Some(Refusal::TableFull { abandoned: 0 }),
        "a data submit beside busy data and metadata slots refuses table-full"
    );
}

/// The `None` assertion prevents an unrelated refusal from triggering the expected panic in `refuses_table_full`.
#[test]
#[should_panic(expected = "a data submit beside busy data and metadata slots refuses table-full")]
fn negative_control_five_busy_slots_accept_the_data_submit() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reserved-progress-control");
    occupy(&mut table, &arena, 5);
    let refusal = data_submit_refusal(&mut table, &arena);
    assert_eq!(
        refusal, None,
        "the planted free slot accepts the data submit"
    );
    refuses_table_full(refusal);
}

#[test]
fn every_data_and_metadata_slot_busy_leaves_the_separate_report_share_and_tick_quota() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reserved-progress");
    occupy(&mut table, &arena, 6);
    refuses_table_full(data_submit_refusal(&mut table, &arena));
    let early = table
        .submit_reservation(ReservationCommand::Report { not_before: 7 }, 6)
        .unwrap_err();
    assert_eq!(early, Refusal::NotBefore);
    SCRIPT.with_borrow_mut(|s| s.report_bytes = report(1));
    let first = table
        .submit_reservation(ReservationCommand::Report { not_before: 7 }, 7)
        .unwrap();
    let quota = table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 7)
        .unwrap_err();
    assert_eq!(quota, Refusal::TickQuota);
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 8)
        .unwrap();
    assert_eq!((table.report().free_slots, table.report().pending), (0, 8));
    conservation(&table, &arena);
    let full = table
        .submit_reservation(ReservationCommand::Report { not_before: 9 }, 9)
        .unwrap_err();
    assert_eq!(full, Refusal::TableFull { abandoned: 0 });
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    let event = out.iter().find(|e| e.token() == first).unwrap();
    assert!(matches!(
        event,
        Terminal::Reservation {
            status: Some(crate::storage::DeviceStatus::Nvme(0)),
            ..
        }
    ));
    let mut entries = [dummy(); 3];
    let parsed = parse_extended_report(
        table.reservation_report(first).unwrap(),
        bounds(),
        7,
        &mut entries,
    )
    .unwrap();
    assert_eq!(parsed.entries[0].pair.exhid.bytes(), [1; 16]);
    drop(out);
    assert_eq!(arena.report(PoolKind::Reservation).free, 0);
    conservation(&table, &arena);
}

#[test]
fn a_report_timeout_keeps_custody_until_its_certified_late_terminal() {
    let arena = arena();
    let mut table = table(&arena, "scripted:report-deadline");
    let token = table
        .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
        .unwrap();
    assert!(table.timeout_report(token));
    assert!(!table.timeout_report(token));
    assert_eq!(
        (table.report().free_slots, table.report().abandoned),
        (7, 1)
    );
    assert_eq!(arena.report(PoolKind::Reservation).quarantined, 1);
    let mut out = Vec::with_capacity(8);
    assert_eq!(
        table.poll(&mut out),
        PollReport {
            delivered: 1,
            stale: 0
        }
    );
    assert_eq!(table.report().stale, 0);
    assert!(
        matches!(out.as_slice(), [Terminal::Reservation { token: t, status: Some(crate::storage::DeviceStatus::Nvme(0)), .. }] if *t == token)
    );
    assert!(table.reservation_report(token).is_none());
    assert!(table.refused_report(token).is_none());
    assert_eq!(table.report().free_slots, 8);
    assert_eq!(table.report().abandoned, 0);
    conservation(&table, &arena);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::AllReturned)
    );
}

#[test]
fn reservation_submission_enomem_recycles_its_buffer_and_delivers_no_terminal() {
    let arena = arena();
    let mut table = table(&arena, "scripted:resv-enomem");
    SCRIPT.with_borrow_mut(|s| s.submit_rc.push_back(-libc::ENOMEM));
    let refused = table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0)
        .unwrap_err();
    assert!(
        matches!(refused,Refusal::Device(r) if r.reason==RefusalReason::QueueFull && r.code==Some(libc::ENOMEM))
    );
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert!(out.is_empty());
    assert_eq!(table.report().pending, 0);
    assert_eq!(arena.report(PoolKind::Reservation).free, 0);
    conservation(&table, &arena);
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0)
        .unwrap();
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 1)
        .unwrap();
    assert_eq!(table.report().pending, 2);
    assert_eq!(table.poll(&mut out).delivered, 2);
    drop(out);
    conservation(&table, &arena);
}

/// Submits a write from `kind`'s pool, completes it with the raw NVMe `status`, and asserts that its terminal fails
/// deposed when `expected_for` is the generic-type Reservation Conflict or Preempt-and-Abort status and as a device
/// failure for every other.
fn fails_as_judged<'a>(
    table: &mut CommandTable<'a, SpdkDisk<'a, Scripted>>,
    arena: &'a BufferArena<TestPlatform>,
    kind: PoolKind,
    status: u16,
    expected_for: u16,
) {
    let submitted = table
        .submit_write(
            arena.acquire(kind).unwrap(),
            DeviceRange::new(0, 4096).unwrap(),
        )
        .unwrap();
    SCRIPT.with_borrow_mut(|s| s.status.push_back(status));
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert!(
        matches!(
            out.as_slice(),
            [Terminal::Failed { token, status: delivered, .. }]
                if *token == submitted && *delivered == crate::storage::DeviceStatus::Nvme(status)
        ),
        "the poll delivers one failed terminal for the submitted write with the scripted status word: {out:?}"
    );
    let expected = if matches!(expected_for, 0x106 | 0x36) {
        Failure::Deposed
    } else {
        Failure::Device
    };
    assert!(
        matches!(&out[0], Terminal::Failed { failure, .. } if *failure == expected),
        "status {status:#x} as {expected_for:#x}: only generic conflict or preempt-abort deposes: {:?}",
        out[0]
    );
}

/// The planted status: the scripted driver completes the command with 0x106, the generic-type Reservation Conflict,
/// where the expectation is for 0x306, the same code under another status type, so the terminal comes back deposed as
/// one judged by its code alone would, and the deposition check rejects it.
#[test]
#[should_panic(expected = "status 0x106 as 0x306: only generic conflict or preempt-abort deposes")]
fn negative_control_a_conflict_status_where_another_type_is_judged_deposes() {
    let arena = arena();
    let mut table = table(&arena, "scripted:deposition-control");
    fails_as_judged(&mut table, &arena, PoolKind::ReceiveWrite, 0x106, 0x306);
}

#[test]
fn only_generic_conflict_and_preempt_abort_depose_payload_and_metadata_commands() {
    let arena = arena();
    let mut table = table(&arena, "scripted:deposition");
    for kind in [PoolKind::ReceiveWrite, PoolKind::Maintenance] {
        for status in [0x106, 0x36, 0x306, 0x1b, 0x104] {
            fails_as_judged(&mut table, &arena, kind, status, status);
        }
    }
    for raw in 0..=u16::MAX {
        let (sc, sct) = ((raw >> 1) & 255, (raw >> 9) & 7);
        assert_eq!(
            crate::storage::DeviceStatus::Nvme(raw).deposes(),
            sct == 0 && matches!(sc, 0x83 | 0x1b)
        );
    }
}

#[test]
fn reservation_callbacks_from_a_submit_or_failed_poll_hold_custody_until_stop() {
    for (index, command) in [
        ReservationCommand::Register { new: key(2) },
        ReservationCommand::Report { not_before: 0 },
        ReservationCommand::Acquire { current: key(2) },
        ReservationCommand::PreemptAndAbort(self_preempt(scripted_pair(key(2)))),
    ]
    .into_iter()
    .enumerate()
    {
        for inline in [false, true] {
            let arena = arena();
            let mut table = table(&arena, &format!("scripted:resv-origin-{index}-{inline}"));
            SCRIPT.with_borrow_mut(|s| {
                s.submit_inline = inline;
                if !inline {
                    s.poll.push_back((-libc::ENXIO, true));
                }
            });
            let token = table.submit_reservation(command, 0).unwrap();
            let mut out = Vec::with_capacity(8);
            assert_eq!(table.poll(&mut out).delivered, 0);
            assert!(out.is_empty());
            assert!(table.reservation_report(token).is_none());
            assert!(table.refused_report(token).is_none());
            assert_eq!(arena.report(PoolKind::Reservation).storage, 1);
            assert_eq!(table.driver_witness().staged, 1);
            table.close();
            assert!(matches!(
                table.quiesce(&mut out),
                QuiesceProgress::Draining { outstanding: 1 }
            ));
            assert_eq!(arena.report(PoolKind::Reservation).storage, 1);
            conservation(&table, &arena);
            assert_eq!(
                table.quiesce(&mut out),
                QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
            );
            assert!(
                matches!(out.as_slice(),[Terminal::Reservation{token:t,status:None,report_error:None}] if *t==token)
            );
            drop(out);
            assert_eq!(arena.report(PoolKind::Reservation).free, 0);
            conservation(&table, &arena);
        }
    }
}

#[test]
fn table_owned_buffers_refuse_a_second_volume_sharing_an_exhausted_reservation_pool() {
    let arena = arena();
    let first = table(&arena, "scripted:physical-reserve-first");
    assert_eq!(arena.report(PoolKind::Reservation).free, 0);
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:physical-reserve-second", limits(8));
    disk.set_reservation_limits(bounds());
    let mut budget = EngineBudget::new(usize::MAX);
    let before = budget;
    let (error, _) = CommandTable::new(disk, &arena, 8, &mut budget).unwrap_err();
    assert_eq!(error, crate::storage::TableError::ReservationReserve);
    assert_eq!(budget, before);
    assert_eq!(first.report().pending, 0);
    drop(first);
    assert_eq!(arena.report(PoolKind::Reservation).free, 2);
}

#[test]
fn attach_refuses_when_read_metadata_and_report_shares_reach_depth() {
    let pools = [
        PoolKind::ReadResponse,
        PoolKind::ReceiveWrite,
        PoolKind::Maintenance,
        PoolKind::Reservation,
    ]
    .map(|kind| PoolSpec {
        kind,
        count: 8,
        buffer_len: 16384,
    });
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    let arena = BufferArena::initialize(
        &config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    let mut storage = crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    storage.read_commands = 5;
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:attach-reservation-sum", limits(8));
    disk.set_reservation_limits(bounds());
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
    let mut budget = EngineBudget::new(usize::MAX);
    let before = budget;
    let (error, _) = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_limits(bounds()),
        8,
        crate::storage::volume_fixture::TICK,
        &mut budget,
    )
    .err()
    .expect("share sum refuses");
    assert_eq!(
        error,
        crate::storage::volume::AttachError::MetadataCommandsOutOfRange {
            read_commands: 5,
            metadata_commands: 1,
            reservation_commands: 2,
            depth: 8
        }
    );
    assert_eq!(budget, before);
    assert_eq!(arena.report(PoolKind::Reservation).free, 8);
    assert!(!super::disk_tests::calls().contains(&Call::Submit));
}

#[test]
fn a_report_snapshot_is_readable_only_after_healthy_success_and_before_its_buffer_reuse() {
    let arena = arena();
    let mut table = table(&arena, "scripted:report-snapshot-lifetime");
    SCRIPT.with_borrow_mut(|s| s.report_bytes = report(1));
    let first = table
        .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
        .unwrap();
    assert!(table.reservation_report(first).is_none());
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert_eq!(
        table.reservation_report(first).unwrap(),
        report(1)
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, 128))
            .collect::<Vec<_>>()
    );
    let failed = table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    assert!(table.reservation_report(first).is_none());
    SCRIPT.with_borrow_mut(|s| s.status.push_back(0x104));
    table.poll(&mut out);
    assert!(table.reservation_report(failed).is_none());
    assert!(table.refused_report(failed).is_none());
    assert!(table.refused_report(first).is_none());
    assert!(matches!(
        out.as_slice(),
        [
            Terminal::Reservation {
                status: Some(crate::storage::DeviceStatus::Nvme(0)),
                ..
            },
            Terminal::Reservation {
                status: Some(crate::storage::DeviceStatus::Nvme(0x104)),
                ..
            }
        ]
    ));
    conservation(&table, &arena);
}

#[test]
fn a_non_holder_enables_reservation_dma_before_canary_while_data_stays_refused() {
    SCRIPT.take();
    let arena = arena();
    let env = crate::native::Environment::detached();
    let mut registration = crate::native::registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:non-holder-before-canary",
        limits(8),
        &mut registration,
    );
    disk.set_reservation_limits(bounds());
    let other = crate::native::registration_tests::ready(&env, &arena);
    assert_eq!(
        disk.enable_reservations(&other).unwrap_err().reason,
        RefusalReason::NotVerified
    );
    disk.enable_reservations(&registration).unwrap();
    let mut table = CommandTable::new(disk, &arena, 8, &mut EngineBudget::new(usize::MAX)).unwrap();
    let mut out = Vec::with_capacity(8);
    for (ordinal, command) in [
        ReservationCommand::Register { new: key(2) },
        ReservationCommand::Report { not_before: 1 },
        ReservationCommand::PreemptAndAbort(self_preempt(scripted_pair(key(2)))),
    ]
    .into_iter()
    .enumerate()
    {
        table.submit_reservation(command, ordinal as u64).unwrap();
        assert_eq!(table.poll(&mut out).delivered, 1);
        drop(out.pop());
    }
    let before = super::disk_tests::calls();
    let refused = table
        .submit_read(
            arena.acquire(PoolKind::ReadResponse).unwrap(),
            DeviceRange::new(0, 4096).unwrap(),
        )
        .unwrap_err();
    assert!(matches!(refused.refusal,Refusal::Device(r) if r.reason==RefusalReason::NotVerified));
    assert_eq!(super::disk_tests::calls(), before);
    for call in [Call::Register, Call::Report, Call::Acquire] {
        assert!(before.contains(&call));
    }
    assert_eq!(table.report().pending, 0);
    conservation(&table, &arena);
}

const _: () =
    assert!(std::mem::offset_of!(spdk_sys::spdk_nvme_reservation_status_data, rtype) == 4);
const _: () =
    assert!(std::mem::offset_of!(spdk_sys::spdk_nvme_reservation_status_data, regctl) == 5);
const _: () =
    assert!(std::mem::size_of::<spdk_sys::spdk_nvme_reservation_status_extended_data>() == 64);
const _: () =
    assert!(std::mem::offset_of!(spdk_sys::spdk_nvme_registered_ctrlr_extended_data, rkey) == 8);
const _: () =
    assert!(std::mem::offset_of!(spdk_sys::spdk_nvme_registered_ctrlr_extended_data, hostid) == 16);
const _: () =
    assert!(std::mem::size_of::<spdk_sys::spdk_nvme_registered_ctrlr_extended_data>() == 64);

#[test]
fn report_groups_one_pair_across_controllers_and_refuses_a_key_under_another_exhid() {
    let mut bytes = report(3);
    bytes[136..144].copy_from_slice(&key(1).encode().to_le_bytes());
    bytes[144..160].fill(1);
    bytes[130] = 1;
    let mut entries = [dummy(); 3];
    let parsed = parse_extended_report(&bytes, bounds(), 0, &mut entries).unwrap();
    assert_eq!(parsed.entries.len(), 3);
    assert_eq!(
        parsed.holding(&crate::failover::bounds::Bounds::new(3, 2, 100, 10, 20, 5).unwrap()),
        crate::failover::evidence::Holding::One(dummy().pair)
    );
    bytes[144..160].fill(2);
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 0, &mut entries),
        Err(ReportError::DuplicateKey)
    );
}

#[test]
fn report_entries_order_by_epoch_then_incarnation_and_a_split_key_refuses_only_under_different_exhids()
 {
    let set = |bytes: &mut [u8], n: usize, cntlid: u16, raw: u64, exhid: u8| {
        let entry = &mut bytes[64 + 64 * n..64 + 64 * (n + 1)];
        entry[..2].copy_from_slice(&cntlid.to_le_bytes());
        entry[8..16].copy_from_slice(&raw.to_le_bytes());
        entry[16..32].fill(exhid);
    };
    let mut bytes = report(3);
    set(&mut bytes, 0, 20, (2 << 32) | 1, 4);
    set(&mut bytes, 1, 21, (1 << 32) | 9, 5);
    set(&mut bytes, 2, 22, (1 << 32) | 2, 6);
    let mut entries = [dummy(); 3];
    let parsed = parse_extended_report(&bytes, bounds(), 0, &mut entries).unwrap();
    assert_eq!(
        parsed
            .entries
            .iter()
            .map(|entry| (entry.cntlid, entry.pair.key.encode()))
            .collect::<Vec<_>>(),
        [
            (22, (1 << 32) | 2),
            (21, (1 << 32) | 9),
            (20, (2 << 32) | 1)
        ]
    );
    set(&mut bytes, 2, 22, (2 << 32) | 1, 6);
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 0, &mut entries),
        Err(ReportError::DuplicateKey)
    );
    set(&mut bytes, 2, 22, (2 << 32) | 1, 4);
    let parsed = parse_extended_report(&bytes, bounds(), 0, &mut entries).unwrap();
    assert_eq!(
        parsed
            .entries
            .iter()
            .map(|entry| entry.pair.key.encode())
            .collect::<Vec<_>>(),
        [(1 << 32) | 9, (2 << 32) | 1, (2 << 32) | 1]
    );
}

#[test]
fn a_key_under_two_exhids_refuses_in_every_row_order_and_one_exhid_decodes_in_key_order() {
    let raw = |value: u64| Key::decode(value).unwrap();
    let split = [
        (4, raw((2 << 32) | 3), false),
        (4, raw((2 << 32) | 3), false),
        (5, raw((2 << 32) | 3), false),
        (6, raw((2 << 32) | 1), false),
        (7, raw((1 << 32) | 9), false),
    ];
    let mut joined = split;
    joined[2].0 = 4;
    let limits = ReservationLimits::new(5, 2, 10, 20).unwrap();
    let mut entries = [dummy(); 5];
    let mut orders = 0;
    for code in 0..5usize.pow(5) {
        let order: [usize; 5] = std::array::from_fn(|n| code / 5usize.pow(n as u32) % 5);
        if (0..5).any(|row| !order.contains(&row)) {
            continue;
        }
        orders += 1;
        assert_eq!(
            parse_extended_report(&rows(&order.map(|row| split[row])), limits, 0, &mut entries),
            Err(ReportError::DuplicateKey),
            "{order:?}"
        );
        let parsed = parse_extended_report(
            &rows(&order.map(|row| joined[row])),
            limits,
            0,
            &mut entries,
        )
        .unwrap();
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|entry| (entry.pair.key.encode(), entry.pair.exhid.bytes()))
                .collect::<Vec<_>>(),
            [
                ((1 << 32) | 9, [7; 16]),
                ((2 << 32) | 1, [6; 16]),
                ((2 << 32) | 3, [4; 16]),
                ((2 << 32) | 3, [4; 16]),
                ((2 << 32) | 3, [4; 16])
            ],
            "{order:?}"
        );
    }
    assert_eq!(orders, 120);
}

#[test]
fn report_fields_preserve_controller_id_key_halves_and_exhid_byte_order() {
    let mut bytes = report(1);
    bytes[64..66].copy_from_slice(&0x1234u16.to_le_bytes());
    bytes[72..80].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    bytes[80..96].copy_from_slice(b"0123456789abcdef");
    let mut entries = [dummy(); 3];
    let parsed = parse_extended_report(&bytes, bounds(), 11, &mut entries).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    let entry = parsed.entries[0];
    assert_eq!(entry.cntlid, 0x1234);
    assert_eq!(entry.pair.key.encode(), 0x0102_0304_0506_0708);
    assert_eq!(entry.pair.exhid.bytes(), *b"0123456789abcdef");
}

#[test]
fn report_output_identity_type_and_bound_refusals_are_distinct() {
    let mut entries = [dummy(); 3];
    assert_eq!(
        parse_extended_report(&report(3), bounds(), 0, &mut entries[..2]),
        Err(ReportError::OutputShort)
    );
    let mut bytes = report(1);
    bytes[80..96].fill(0);
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 0, &mut entries),
        Err(ReportError::Identity(
            crate::failover::identity::IdentityError::ExhidZero
        ))
    );
    bytes[80..96].fill(1);
    bytes[4] = 0;
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 0, &mut entries)
            .unwrap()
            .rtype,
        ReservationType::None
    );
    bytes[5] = 4;
    assert_eq!(
        parse_extended_report(&bytes, bounds(), 0, &mut entries),
        Err(ReportError::Inconclusive { regctl: 4 })
    );
}

/// Report bytes whose rows all read controller ID 65535: `rows` of `(host ID byte, key, holder)`.
fn rows(rows: &[(u8, Key, bool)]) -> Vec<u8> {
    let mut bytes = vec![0; 64 + 64 * rows.len()];
    bytes[4] = 2;
    bytes[5..7].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    for (n, &(host, key, holder)) in rows.iter().enumerate() {
        let entry = &mut bytes[64 + 64 * n..64 + 64 * (n + 1)];
        entry[..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        entry[2] = u8::from(holder);
        entry[8..16].copy_from_slice(&key.encode().to_le_bytes());
        entry[16..32].fill(host);
    }
    bytes
}

/// Submits one Report of `bytes` on `table` and returns its terminal's identity refusal and the bytes
/// `reservation_report` exposes, after checking that `refused_report` exposes the written bytes for a refused Report
/// and nothing for a passed one.
fn report_through(
    table: &mut CommandTable<'_, SpdkDisk<'_, Scripted>>,
    bytes: Vec<u8>,
) -> (Option<ReportError>, Option<Vec<u8>>) {
    SCRIPT.with_borrow_mut(|s| s.report_bytes = bytes);
    let token = table
        .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
        .unwrap();
    let mut out = Vec::with_capacity(8);
    assert_eq!(table.poll(&mut out).delivered, 1);
    let [
        Terminal::Reservation {
            token: seen,
            report_error,
            ..
        },
    ] = out.as_slice()
    else {
        panic!("one reservation terminal");
    };
    assert_eq!(*seen, token);
    let (checked, refused) = (table.reservation_report(token), table.refused_report(token));
    if report_error.is_some() {
        assert!(checked.is_none());
        let written = SCRIPT.with_borrow(|s| s.report_bytes.clone());
        assert!(refused.is_some_and(|bytes| bytes.starts_with(&written)));
    } else {
        assert!(refused.is_none());
    }
    (*report_error, checked.map(<[u8]>::to_vec))
}

/// With controller ID 65535 on every row, the own record is the one row with the own host ID and key: the
/// Report passes its identity check wherever that row sits, its parsed evidence names the own pair as holder,
/// and a self preempt builds from it. Under another key, or with the own pair not holding, no self preempt
/// builds.
#[test]
fn own_record_by_host_id_not_controller_id() {
    let own = scripted_pair(key(1));
    for (name, layout) in [
        ("first", [(1, key(1), true), (5, key(3), false)]),
        ("second", [(5, key(3), false), (1, key(1), true)]),
    ] {
        let arena = arena();
        let mut table = table(&arena, &format!("scripted:own-record-{name}"));
        let (refusal, bytes) = report_through(&mut table, rows(&layout));
        assert_eq!(refusal, None, "{name}");
        let mut entries = [dummy(); 3];
        let report = parse_extended_report(&bytes.unwrap(), bounds(), 0, &mut entries).unwrap();
        assert!(report.entries.iter().all(|entry| entry.cntlid == 0xFFFF));
        assert_eq!(
            crate::storage::SelfPreempt::from_report(&report, &preempt_bounds(), own)
                .map(|p| p.pair()),
            Some(own)
        );
        let foreign_key = Pair { key: key(4), ..own };
        assert_eq!(
            crate::storage::SelfPreempt::from_report(&report, &preempt_bounds(), foreign_key),
            None
        );
        conservation(&table, &arena);
    }
    let mut entries = [dummy(); 3];
    let bytes = rows(&[(1, key(1), false), (5, key(3), true)]);
    let report = parse_extended_report(&bytes, bounds(), 0, &mut entries).unwrap();
    assert_eq!(
        crate::storage::SelfPreempt::from_report(&report, &preempt_bounds(), own),
        None,
        "own pair not holding"
    );
}

/// The own-record count over raw rows: one own row under the own key passes, as does a Report with no own row;
/// two own rows, the own host ID under another key, and a trailing partial row refuse. The driver applies the
/// count with its persisted key, so a Report showing the own host ID under another key refuses on the table and
/// `reservation_report` withholds its bytes.
#[test]
fn own_record_count_refuses_an_alias_a_foreign_key_and_a_partial_row() {
    use crate::storage::check_own_record;
    let own = scripted_pair(key(1));
    let one = rows(&[(1, key(1), true), (5, key(3), false)]);
    assert_eq!(check_own_record(&one[64..], own), Ok(()));
    assert_eq!(
        check_own_record(&rows(&[(5, key(3), true)])[64..], own),
        Ok(())
    );
    assert_eq!(
        check_own_record(&rows(&[(1, key(1), true), (1, key(2), false)])[64..], own),
        Err(ReportError::DuplicateOwnHostId { records: 2 })
    );
    assert_eq!(
        check_own_record(&rows(&[(1, key(3), true)])[64..], own),
        Err(ReportError::OwnHostIdKey)
    );
    let mut partial = rows(&[(1, key(1), true), (1, key(1), false)]);
    partial.truncate(64 + 64 + 32);
    assert_eq!(
        check_own_record(&partial[64..], own),
        Err(ReportError::Truncated)
    );

    let arena = arena();
    let mut table = table(&arena, "scripted:own-host-id-key");
    assert_eq!(
        report_through(&mut table, rows(&[(1, key(3), true)])),
        (Some(ReportError::OwnHostIdKey), None)
    );
    conservation(&table, &arena);
}

#[test]
fn only_own_host_id_refusals_map_to_duplicate_own_record() {
    use crate::failover::identity::IdentityError;
    for (error, duplicate_own_record) in [
        (ReportError::DuplicateOwnHostId { records: 2 }, true),
        (ReportError::OwnHostIdKey, true),
        (ReportError::Truncated, false),
        (ReportError::ExhidLength, false),
        (ReportError::Identity(IdentityError::ExhidZero), false),
        (ReportError::DuplicateKey, false),
        (ReportError::ReservationType(1), false),
        (ReportError::Inconclusive { regctl: 4 }, false),
        (ReportError::OutputShort, false),
        (ReportError::Unchecked, false),
    ] {
        assert_eq!(
            error.refusal() == NotSole::DuplicateOwnRecord,
            duplicate_own_record,
            "{error:?}"
        );
    }
}

#[test]
fn every_report_parse_refusal_maps_to_its_sole_registrant_refusal() {
    use crate::failover::identity::IdentityError;
    for (error, expected) in [
        (ReportError::Truncated, NotSole::Unreadable),
        (ReportError::ExhidLength, NotSole::Unreadable),
        (
            ReportError::Identity(IdentityError::ExhidZero),
            NotSole::ForeignRegistrant,
        ),
        (ReportError::DuplicateKey, NotSole::ForeignRegistrant),
        (
            ReportError::DuplicateOwnHostId { records: 2 },
            NotSole::DuplicateOwnRecord,
        ),
        (ReportError::OwnHostIdKey, NotSole::DuplicateOwnRecord),
        (ReportError::ReservationType(1), NotSole::ReservationType),
        (ReportError::Inconclusive { regctl: 9 }, NotSole::Excess),
        (ReportError::OutputShort, NotSole::Unreadable),
        (ReportError::Unchecked, NotSole::Unreadable),
    ] {
        assert_eq!(error.refusal(), expected, "{error:?}");
    }
}

/// A self preempt builds only from a Report whose bounded holding is the own pair alone, under type 2, with one
/// record carrying the own host ID: a second own-host-ID record under a higher key, type 0 with the holder bit, a
/// foreign co-holder, a header count the entries do not match and a header over the bound each refuse.
#[test]
fn self_preempt_requires_the_own_pair_as_the_one_type_2_holder() {
    use crate::storage::SelfPreempt;
    let own = scripted_pair(key(2));
    let parsed = |bytes: Vec<u8>| {
        let mut entries = [dummy(); 3];
        let report = parse_extended_report(&bytes, bounds(), 0, &mut entries).unwrap();
        SelfPreempt::from_report(&report, &preempt_bounds(), own)
    };
    assert_eq!(
        parsed(rows(&[(1, key(2), true), (5, key(3), false)])).map(SelfPreempt::pair),
        Some(own)
    );
    assert_eq!(
        parsed(rows(&[(1, key(2), true), (1, key(3), false)])),
        None,
        "a second record with the own host ID"
    );
    let mut untyped = rows(&[(1, key(2), true)]);
    untyped[4] = 0;
    assert_eq!(
        parsed(untyped),
        None,
        "reservation type 0 with the holder bit"
    );
    assert_eq!(
        parsed(rows(&[(1, key(2), true), (5, key(3), true)])),
        None,
        "a foreign co-holder"
    );
    let holder = Registrant {
        cntlid: 0xFFFF,
        holder: true,
        pair: own,
    };
    let other = |n: u8| Registrant {
        cntlid: 0xFFFF,
        holder: false,
        pair: Pair {
            exhid: Exhid::new([n; 16]).unwrap(),
            key: key(u64::from(n)),
        },
    };
    for (regctl, entries, name) in [
        (2, vec![holder], "a header count the entries do not match"),
        (
            4,
            vec![holder, other(5), other(6), other(7)],
            "a header over the bound",
        ),
    ] {
        let report = crate::failover::evidence::Report {
            submitted_at: 0,
            rtype: ReservationType::ExclusiveAccess,
            regctl,
            entries: &entries,
        };
        assert_eq!(
            SelfPreempt::from_report(&report, &preempt_bounds(), own),
            None,
            "{name}"
        );
    }
}

#[test]
fn an_authority_disk_refuses_the_canary_reads_and_writes() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink};
    for authority in [true, false] {
        SCRIPT.take();
        let (env, arena) = (Environment::detached(), registration_tests::new_arena());
        let mut registration = registration_tests::ready(&env, &arena);
        let mut disk = SpdkDisk::<Scripted>::scripted_leased(
            "scripted:authority-gate",
            limits(8),
            &mut registration,
        );
        if authority {
            disk.set_authority(crate::bind::authority_tests::prepared());
            let canary = arena.acquire(PoolKind::ReceiveWrite).unwrap();
            match disk.canary(&registration, canary, std::time::Duration::from_secs(1)) {
                Err(super::disk::CanaryError::Refused(refusal)) => {
                    assert_eq!(refusal.reason, RefusalReason::NotVerified)
                }
                other => panic!("the canary under an authority refuses, got {other:?}"),
            }
            assert!(
                super::disk_tests::calls().is_empty(),
                "the refused canary reaches the device"
            );
        }
        let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
        let memory = buffer.range(4096).unwrap();
        disk.mark_verified(memory);
        // SAFETY: a refused read keeps the exclusive buffer with the caller, and an admitted one holds it until its
        // terminal is picked below.
        let read = unsafe {
            disk.submit_read(
                CommandToken::from_raw(40),
                DeviceRange::new(0, 4096).unwrap(),
                memory,
            )
        };
        if authority {
            assert_eq!(read.unwrap_err().reason, RefusalReason::NotVerified);
            for offset in [0, 4096, 8192] {
                // SAFETY: every refused write leaves the buffer in caller custody.
                let write = unsafe {
                    disk.submit_write(
                        CommandToken::from_raw(offset),
                        DeviceRange::new(offset, 4096).unwrap(),
                        memory,
                    )
                };
                assert_eq!(write.unwrap_err().reason, RefusalReason::NotVerified);
            }
            assert!(
                super::disk_tests::calls().is_empty(),
                "no command reaches the device"
            );
        } else {
            read.unwrap();
            let mut reads = Vec::with_capacity(1);
            disk.pick_completions(&mut CompletionSink::new(&mut reads, 1));
            assert_eq!(reads.len(), 1, "the control without an authority reads");
        }
        assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
        assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
        registration
            .device_stopped(disk.stop_proof().unwrap())
            .unwrap();
        assert!(disk.detach(&registration_tests::undone(registration)));
    }
}

/// When a table Report contains two records with the own host ID, the terminal records the identity refusal and
/// `reservation_report` withholds the refused Report's bytes as ownership evidence. On the serving volume, a poll Report
/// deposes the volume with the own-host-ID cause for the duplicate, for an alias co-holding under the own key, for
/// the own host ID under another key, and for a duplicate among the visible rows of a header over the bound. The
/// serving token's pair decides the same shapes when the driver, connected under another host ID, passes them.
#[test]
fn duplicate_own_host_id_refuses_then_retires() {
    let arena = arena();
    let mut table = table(&arena, "scripted:duplicate-own-before");
    let duplicate = rows(&[(1, key(2), true), (1, key(2), false), (5, key(3), false)]);
    assert_eq!(
        report_through(&mut table, duplicate.clone()),
        (Some(ReportError::DuplicateOwnHostId { records: 2 }), None)
    );
    conservation(&table, &arena);

    use crate::failover::serving::State;
    let mut over_bound = duplicate.clone();
    over_bound[5] = 4;
    let other_host = Pair {
        exhid: Exhid::new([2; 16]).unwrap(),
        key: key(2),
    };
    let co_holder = rows(&[(1, key(2), true), (1, key(2), true), (5, key(3), false)]);
    let other_key = rows(&[(1, key(3), true)]);
    for (name, bytes, driver) in [
        ("duplicate", duplicate.clone(), scripted_pair(key(2))),
        ("co-holder", co_holder.clone(), scripted_pair(key(2))),
        ("other key", other_key.clone(), scripted_pair(key(2))),
        ("over the bound", over_bound, scripted_pair(key(2))),
        ("parsed duplicate", duplicate, other_host),
        ("parsed co-holder", co_holder, other_host),
        ("parsed other key", other_key, other_host),
    ] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume_with(&storage, &arena, &time, driver);
        assert_eq!(volume.authority_report().state, State::Serving, "{name}");
        SCRIPT.with_borrow_mut(|s| s.report_bytes = bytes);
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.authority_report().state, State::Withdrawn, "{name}");
        assert_eq!(
            volume.authority_report().refusal,
            Some(crate::storage::AuthorityRefusal::OwnHostId),
            "{name}"
        );
        volume.close();
    }
}

#[test]
fn reservation_first_saturation_preserves_the_entire_data_share() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reservation-first-share");
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0)
        .unwrap();
    table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    for _ in 0..6 {
        table
            .submit_write(
                arena.acquire(PoolKind::ReceiveWrite).unwrap(),
                DeviceRange::new(0, 4096).unwrap(),
            )
            .unwrap();
    }
    let rejected = table
        .submit_write(
            arena.acquire(PoolKind::ReceiveWrite).unwrap(),
            DeviceRange::new(0, 4096).unwrap(),
        )
        .unwrap_err();
    assert_eq!(rejected.refusal, Refusal::TableFull { abandoned: 0 });
    drop(rejected);
    conservation(&table, &arena);
    let mut out = Vec::with_capacity(8);
    assert_eq!(table.poll(&mut out).delivered, 8);
    drop(out);
    conservation(&table, &arena);
}

#[test]
fn report_timeout_refuses_other_command_kinds_and_cancelled_report_recycles_at_terminal() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reservation-cancel-kind");
    let data = table
        .submit_read(
            arena.acquire(PoolKind::ReadResponse).unwrap(),
            DeviceRange::new(0, 4096).unwrap(),
        )
        .unwrap();
    let acquire = table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0)
        .unwrap();
    let before = (
        table.report(),
        arena.report(PoolKind::Reservation),
        arena.report(PoolKind::ReadResponse),
    );
    assert!(!table.timeout_report(data));
    assert!(!table.timeout_report(acquire));
    assert_eq!(
        (
            table.report(),
            arena.report(PoolKind::Reservation),
            arena.report(PoolKind::ReadResponse)
        ),
        before
    );
    let mut out = Vec::with_capacity(8);
    assert_eq!(table.poll(&mut out).delivered, 2);
    out.clear();
    let token = table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    table.cancel(token).unwrap();
    assert_eq!(table.poll(&mut out).delivered, 1);
    assert!(
        matches!(out.as_slice(), [Terminal::Reservation { token: seen, status: Some(crate::storage::DeviceStatus::Nvme(0)), report_error: None }] if *seen == token)
    );
    assert!(table.reservation_report(token).is_none());
    conservation(&table, &arena);
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 2)
        .unwrap();
    out.clear();
    assert_eq!(table.poll(&mut out).delivered, 1);
    conservation(&table, &arena);
}

#[test]
fn reservation_admission_refuses_before_report_time_quota_and_exhausted_buffers() {
    for (name, admission) in [
        ("closed", Refusal::Closed),
        ("lost", Refusal::DeviceLost),
        ("stopped", Refusal::Stopped),
    ] {
        let arena = arena();
        let mut table = table(&arena, &format!("scripted:reservation-admission-{name}"));
        table
            .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
            .unwrap();
        table
            .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 1)
            .unwrap();
        match name {
            "closed" => table.close(),
            "lost" => {
                SCRIPT.with_borrow_mut(|s| s.poll.push_back((-libc::ENXIO, false)));
                table.poll(&mut Vec::with_capacity(8));
                let rejected = table
                    .submit_read(
                        arena.acquire(PoolKind::ReadResponse).unwrap(),
                        DeviceRange::new(0, 4096).unwrap(),
                    )
                    .unwrap_err();
                assert!(
                    matches!(rejected.refusal, Refusal::Device(r) if r.reason == RefusalReason::DeviceGone)
                );
            }
            "stopped" => {
                SCRIPT.with_borrow_mut(|s| s.poll.extend([(0, false), (0, false)]));
                let mut out = Vec::with_capacity(8);
                assert!(matches!(
                    table.quiesce(&mut out),
                    QuiesceProgress::Draining { .. }
                ));
                assert!(matches!(
                    table.quiesce(&mut out),
                    QuiesceProgress::Quiesced(_)
                ));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            table.submit_reservation(ReservationCommand::Report { not_before: 99 }, 1),
            Err(admission)
        );
        if name != "stopped" {
            let mut out = Vec::with_capacity(8);
            while !matches!(table.quiesce(&mut out), QuiesceProgress::Quiesced(_)) {
                out.clear();
            }
        }
    }
}

#[test]
fn reservation_reserve_validates_depth_buffer_length_and_max_transfer_before_charge() {
    let arena = arena_with_len(16384);
    for (name, depth, reserve) in [
        ("depth", 2, bounds()),
        ("buffer", 8, ReservationLimits::new(256, 2, 10, 20).unwrap()),
        (
            "transfer",
            8,
            ReservationLimits::new(64, 2, 10, 20).unwrap(),
        ),
    ] {
        let mut geometry = limits(8);
        if name == "transfer" {
            geometry.transfer = 4096;
        }
        let mut disk =
            SpdkDisk::<Scripted>::scripted(&format!("scripted:reserve-{name}"), geometry);
        disk.set_reservation_limits(reserve);
        let mut budget = EngineBudget::new(usize::MAX);
        let before = (budget, arena.report(PoolKind::Reservation));
        let (error, _) = CommandTable::new(disk, &arena, depth, &mut budget).unwrap_err();
        assert_eq!(error, crate::storage::TableError::ReservationReserve);
        assert_eq!((budget, arena.report(PoolKind::Reservation)), before);
    }
    let disk = SpdkDisk::<Scripted>::scripted("scripted:no-reservation-share", limits(8));
    let mut table = CommandTable::new(disk, &arena, 8, &mut EngineBudget::new(usize::MAX)).unwrap();
    assert!(
        matches!(table.submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0), Err(Refusal::Device(r)) if r.reason == RefusalReason::Unsupported)
    );
    let buffer = arena.acquire(PoolKind::Reservation).unwrap();
    let offset = buffer.offset();
    let rejected = table
        .submit_write(buffer, DeviceRange::new(0, 4096).unwrap())
        .unwrap_err();
    assert_eq!(rejected.refusal, Refusal::ReservationBuffer);
    assert_eq!(rejected.buffer.offset(), offset);
    assert!(super::disk_tests::calls().is_empty());
}

#[test]
fn successful_volume_attach_subtracts_and_charges_the_physical_reservation_share() {
    let arena = arena_with_len(16384);
    let mut storage = crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    storage.read_commands = 4;
    let mut disk = SpdkDisk::<Scripted>::scripted("scripted:reservation-attach-charge", limits(8));
    disk.set_reservation_limits(bounds());
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
    let tick = crate::storage::volume_fixture::TICK;
    let clock = crate::storage::portable::scripted::ScriptedClock::trusted();
    let charge = crate::storage::Volume::attach_charge(
        &storage,
        &arena,
        &disk,
        &*clock,
        &crate::storage::ServingAuthority::fixture_limits(bounds()),
        8,
        tick,
    )
    .unwrap();
    let mut short = EngineBudget::new(charge - 1);
    let (error, disk) = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        clock,
        crate::storage::ServingAuthority::fixture_limits(bounds()),
        8,
        tick,
        &mut short,
    )
    .err()
    .unwrap();
    assert!(matches!(
        error,
        crate::storage::volume::AttachError::Envelope(_)
    ));
    assert_eq!(short.used(), 0);
    assert_eq!(arena.report(PoolKind::Reservation).free, 2);
    let held = arena.acquire(PoolKind::Reservation).unwrap();
    let mut budget = EngineBudget::new(charge);
    let (error, disk) = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_limits(bounds()),
        8,
        tick,
        &mut budget,
    )
    .err()
    .unwrap();
    assert_eq!(
        error,
        crate::storage::volume::AttachError::Table(crate::storage::TableError::ReservationReserve)
    );
    assert_eq!(budget.used(), 0);
    drop(held);
    let volume = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture_limits(bounds()),
        8,
        tick,
        &mut budget,
    )
    .unwrap();
    assert_eq!(volume.write_share(), 1);
    assert_eq!(
        (
            arena.report(PoolKind::Reservation).free,
            arena.report(PoolKind::Reservation).application
        ),
        (0, 2)
    );
    assert_eq!(budget.used(), charge);
    assert!(!super::disk_tests::calls().contains(&Call::Submit));
    drop(volume);
    assert_eq!(arena.report(PoolKind::Reservation).free, 2);
}

#[test]
fn a_conflict_read_terminal_carries_deposition_while_other_statuses_keep_their_class() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reservation-read-deposition");
    for raw in [0x106, 0x36, 0x306, 0x104] {
        table
            .submit_read(
                arena.acquire(PoolKind::ReadResponse).unwrap(),
                DeviceRange::new(0, 4096).unwrap(),
            )
            .unwrap();
        SCRIPT.with_borrow_mut(|s| s.status.push_back(raw));
        let mut out = Vec::with_capacity(8);
        assert_eq!(table.poll(&mut out).delivered, 1);
        let expected = if matches!(raw, 0x106 | 0x36) {
            Failure::Deposed
        } else {
            Failure::Device
        };
        assert!(
            matches!(out.as_slice(), [Terminal::Failed { op: crate::storage::Operation::Read, failure, .. }] if *failure == expected)
        );
        drop(out);
        conservation(&table, &arena);
    }
}

#[test]
fn reservation_submit_preserves_the_native_gone_errno() {
    let arena = arena();
    let mut table = table(&arena, "scripted:reservation-gone-errno");
    table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 0)
        .unwrap();
    SCRIPT.with_borrow_mut(|s| s.poll.push_back((-libc::ENXIO, false)));
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    let refusal = table
        .submit_reservation(ReservationCommand::Acquire { current: key(1) }, 1)
        .unwrap_err();
    assert!(
        matches!(refusal, Refusal::Device(r) if r.reason == RefusalReason::DeviceGone && r.code == Some(libc::ENXIO))
    );
    while !matches!(table.quiesce(&mut out), QuiesceProgress::Quiesced(_)) {
        out.clear();
    }
    conservation(&table, &arena);
}

#[test]
fn reservation_memory_gate_refuses_before_enable_and_checks_exact_length_and_arena() {
    use crate::storage::{CommandToken, Disk, DmaRange};
    SCRIPT.take();
    let arena = arena();
    let env = crate::native::Environment::detached();
    let mut registration = crate::native::registration_tests::registered(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:reservation-memory-gate",
        limits(8),
        &mut registration,
    );
    disk.set_reservation_limits(bounds());
    let buffer = arena.acquire(PoolKind::Reservation).unwrap();
    let range = buffer.range(512).unwrap();
    let memory = DmaRange::new(range.addr(), range.offset(), bounds().report_bytes());
    let command = ReservationCommand::Report { not_before: 0 };
    let before = super::disk_tests::calls();
    assert_eq!(
        disk.enable_reservations(&registration).unwrap_err().reason,
        RefusalReason::NotVerified
    );
    // SAFETY: the exclusive live buffer covers the payload; the verification refusal retains nothing.
    unsafe {
        assert_eq!(
            disk.submit_reservation(CommandToken::from_raw(1), command, memory)
                .unwrap_err()
                .reason,
            RefusalReason::NotVerified
        );
    }
    assert_eq!(super::disk_tests::calls(), before);
    registration.map().unwrap();
    registration.verify().unwrap();
    disk.enable_reservations(&registration).unwrap();
    let other = arena_with_len(4096);
    let foreign = other.acquire(PoolKind::Reservation).unwrap();
    let range = foreign.range(512).unwrap();
    let foreign = DmaRange::new(range.addr(), range.offset(), bounds().report_bytes());
    for memory in [DmaRange::new(memory.addr(), memory.offset(), 16), foreign] {
        // SAFETY: both ranges lie in exclusive live buffers; range validation refuses before any native call.
        unsafe {
            assert_eq!(
                disk.submit_reservation(CommandToken::from_raw(2), command, memory)
                    .unwrap_err()
                    .reason,
                RefusalReason::InvalidRange
            );
        }
    }
    assert_eq!(super::disk_tests::calls(), before);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&crate::native::registration_tests::undone(registration)));
}

#[test]
fn durable_assignment_pair_reaches_register_and_wrong_keys_issue_zero_commands() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink};
    SCRIPT.take();
    let authority = crate::bind::authority_tests::prepared();
    assert!(super::disk_tests::calls().is_empty());
    let pair = authority.pair();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:authority-register",
        limits(8),
        &mut registration,
    );
    disk.set_reservation_limits(bounds());
    disk.set_authority(authority);
    assert_eq!(disk.authority_pair(), Some(pair));
    let mut opts = spdk_sys::spdk_nvme_ctrlr_opts::default();
    // SAFETY: the writable options carry the pair returned after durable preparation.
    unsafe {
        Spdk::connect_options(&mut opts, pair.exhid.bytes());
    }
    assert_eq!(opts.extended_host_id, [9; 16]);
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(buffer.range(4096).unwrap());
    let bad = ReservationCommand::Register { new: key(1) };
    bad.encode(&mut buffer.bytes_mut()[..16]);
    // SAFETY: the buffer stays exclusive through the refused submission.
    let result = unsafe {
        disk.submit_reservation(
            CommandToken::from_raw(1),
            bad,
            crate::storage::device::disk::DmaRange::new(
                buffer.range(4096).unwrap().addr(),
                buffer.offset(),
                16,
            ),
        )
    };
    assert_eq!(result.unwrap_err().reason, RefusalReason::NotVerified);
    assert!(SCRIPT.with_borrow(|s| s.reservation_calls.is_empty()));
    let command = ReservationCommand::Register { new: pair.key };
    bad.encode(&mut buffer.bytes_mut()[..16]);
    let memory = crate::storage::device::disk::DmaRange::new(
        buffer.range(4096).unwrap().addr(),
        buffer.offset(),
        16,
    );
    // SAFETY: refusal keeps the exclusive buffer in caller custody.
    let mismatched = unsafe { disk.submit_reservation(CommandToken::from_raw(3), command, memory) };
    assert_eq!(mismatched.unwrap_err().reason, RefusalReason::NotVerified);
    assert!(SCRIPT.with_borrow(|s| s.reservation_calls.is_empty()));
    command.encode(&mut buffer.bytes_mut()[..16]);
    // SAFETY: buffer custody remains with the command until its certified terminal below.
    unsafe {
        disk.submit_reservation(
            CommandToken::from_raw(2),
            command,
            crate::storage::device::disk::DmaRange::new(
                buffer.range(4096).unwrap().addr(),
                buffer.offset(),
                16,
            ),
        )
    }
    .unwrap();
    let mut out = Vec::with_capacity(1);
    disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
    assert_eq!(out.len(), 1);
    let calls = SCRIPT.with_borrow(|s| s.reservation_calls.clone());
    assert_eq!(calls.len(), 1);
    assert_eq!((calls[0].0, calls[0].1), (Call::Register, 0));
    assert_eq!(
        u64::from_le_bytes(calls[0].4[8..].try_into().unwrap()),
        (1u64 << 32) | 2
    );
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}

#[test]
fn a_retiring_report_collected_before_its_deadline_withdraws_after_it() {
    use crate::failover::serving::State;
    let other_host = Pair {
        exhid: Exhid::new([2; 16]).unwrap(),
        key: key(2),
    };
    for driver in [scripted_pair(key(2)), other_host] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume_with(&storage, &arena, &time, driver);
        SCRIPT.with_borrow_mut(|s| {
            s.report_bytes = rows(&[(1, key(2), true), (1, key(2), false), (5, key(3), false)]);
        });
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.authority_report().state, State::Serving);
        // The turn's first deadline pass reads 10; the pass after the table collects the terminal reads 25, past
        // the Report deadline.
        JUMP.set(Some((1, 25)));
        volume.poll_storage(0, &mut out);
        JUMP.set(None);
        assert_eq!(time.get(), 25);
        assert_eq!(
            volume.authority_report().state,
            State::Withdrawn,
            "{driver:?}"
        );
        assert_eq!(
            volume.authority_report().refusal,
            Some(crate::storage::AuthorityRefusal::OwnHostId),
            "{driver:?}"
        );
        let report = volume.authority_report();
        assert_eq!(
            report.withdrawal,
            crate::failover::serving::ReportTrigger::new(
                crate::failover::evidence::NotSole::DuplicateOwnRecord
            )
            .map(crate::failover::serving::Cause::Report),
            "{driver:?}"
        );
        assert_eq!(
            report.flip.map(|flip| (flip.generation, flip.attempts)),
            Some((report.tenure.0, report.tenure.1.get() / 2)),
            "{driver:?}"
        );
        volume.close();
    }
}

#[test]
fn a_foreign_report_collected_before_its_deadline_withdraws_after_it() {
    use crate::failover::evidence::NotSole;
    use crate::failover::serving::{Cause, ReportTrigger, State};
    let mut rtype_zero = rows(&[(1, key(2), true)]);
    rtype_zero[4] = 0;
    for (bytes, refusal) in [
        (
            rows(&[(1, key(2), true), (5, key(3), false)]),
            NotSole::ForeignRegistrant,
        ),
        (
            rows(&[(1, key(2), false), (5, key(3), true)]),
            NotSole::ForeignHolder,
        ),
        (rtype_zero, NotSole::ReservationType),
    ] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume(&storage, &arena, &time);
        SCRIPT.with_borrow_mut(|s| s.report_bytes = bytes);
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.authority_report().state, State::Serving);
        JUMP.set(Some((1, 25)));
        volume.poll_storage(0, &mut out);
        JUMP.set(None);
        assert_eq!(time.get(), 25);
        let report = volume.authority_report();
        // NO-HOLDER-HOLD: the own pair alone under no reservation withdraws with no flip request.
        if refusal == NotSole::ReservationType {
            assert_eq!(
                (report.state, report.withdrawal, report.flip),
                (State::Withdrawn, Some(Cause::Unheld), None),
                "{refusal:?}"
            );
            volume.close();
            continue;
        }
        assert_eq!(
            (report.state, report.withdrawal),
            (
                State::Withdrawn,
                ReportTrigger::new(refusal).map(Cause::Report)
            ),
            "{refusal:?}"
        );
        assert_eq!(
            report.flip.map(|flip| (flip.generation, flip.attempts)),
            Some((report.tenure.0, report.tenure.1.get() / 2)),
            "{refusal:?}"
        );
        volume.close();
    }
}

#[test]
fn a_clean_report_collected_before_its_deadline_closes_the_window_after_it() {
    use crate::failover::serving::State;
    let arena = arena_with_len(16384);
    let mut storage = crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    storage.read_commands = 4;
    let time = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut volume = serving_volume(&storage, &arena, &time);
    let mut out = Vec::with_capacity(16);
    time.set(10);
    volume.poll_storage(0, &mut out);
    assert_eq!(volume.authority_report().state, State::Serving);
    JUMP.set(Some((1, 25)));
    volume.poll_storage(0, &mut out);
    JUMP.set(None);
    assert_eq!(time.get(), 25);
    assert_eq!(volume.authority_report().state, State::Serving);
    assert!(
        volume
            .admit_authority(
                crate::failover::serving::Operation::Read,
                volume.serving_token()
            )
            .is_err()
    );
    assert_eq!(
        volume.authority_report().refusal,
        Some(crate::storage::AuthorityRefusal::ReportTimeout)
    );
    volume.close();
}

fn serving_volume<'a>(
    storage: &'a crate::storage::Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    time: &std::rc::Rc<std::cell::Cell<u64>>,
) -> crate::storage::Volume<'a, 'a, TestPlatform, SpdkDisk<'a, Scripted>> {
    serving_volume_with(storage, arena, time, scripted_pair(key(2)))
}

/// A serving volume whose token carries the scripted host ID and `key(2)`, over a driver connected as `driver`.
fn serving_volume_with<'a>(
    storage: &'a crate::storage::Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    time: &std::rc::Rc<std::cell::Cell<u64>>,
    driver: Pair,
) -> crate::storage::Volume<'a, 'a, TestPlatform, SpdkDisk<'a, Scripted>> {
    use crate::failover::{bounds::Bounds, serving::Machine};
    SCRIPT.take();
    let mut own = report(1);
    own[72..80].copy_from_slice(&key(2).encode().to_le_bytes());
    SCRIPT.with_borrow_mut(|s| s.report_bytes = own);
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let address = format!(
        "scripted:serving-volume-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut disk = SpdkDisk::<Scripted>::scripted(&address, limits(8));
    disk.set_own(driver);
    disk.set_reservation_limits(bounds());
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
    let probe = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(probe.range(4096).unwrap());
    drop(probe);
    let limits = Bounds::new(3, 1, 100, 10, 10, 0).unwrap();
    let session = crate::storage::next_session();
    let pair = Pair {
        key: key(2),
        ..dummy().pair
    };
    let machine = Machine::issued(limits, &session, pair);
    let authority = crate::storage::ServingAuthority::new(
        limits,
        machine,
        Box::new(ServingTime(std::rc::Rc::clone(time))),
        session,
    );
    let mut volume = crate::storage::Volume::attach(
        storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        8,
        crate::storage::TickConfig {
            submit_burst: 1,
            ..crate::storage::volume_fixture::TICK
        },
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    crate::storage::volume_fixture::open_polled(&mut volume, 128);
    volume
}

#[test]
fn tokenless_attach_parses_reports_renews_idle_windows_and_counts_the_report_quota() {
    use crate::failover::serving::{Event, State};
    let arena = arena_with_len(16384);
    let mut storage = crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    storage.read_commands = 4;
    let time = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut volume = serving_volume(&storage, &arena, &time);
    assert_eq!(volume.authority_report().state, State::Serving);
    let reports = SCRIPT.with_borrow(|s| s.reservation_calls.len());
    let mut out = Vec::with_capacity(16);
    time.set(10);
    assert_eq!(volume.poll_storage(0, &mut out).submitted, 1);
    assert_eq!(
        SCRIPT.with_borrow(|s| s.reservation_calls.len()),
        reports + 1
    );
    time.set(11);
    volume.poll_storage(0, &mut out);
    assert_eq!(volume.authority_report().state, State::Serving);
    assert_eq!(volume.authority_report().report_age_us, Some(1));
    volume.authority_event(Event::Expire { now: 11 });
    time.set(20);
    assert_eq!(volume.poll_storage(0, &mut out).submitted, 1);
    volume.poll_storage(0, &mut out);
    assert_eq!(volume.authority_report().state, State::Serving);
    assert_eq!(volume.authority_report().report_age_us, Some(0));
    volume.close();
}

#[test]
fn timed_out_report_late_success_establishes_nothing_and_late_conflict_withdraws() {
    use crate::failover::serving::State;
    for status in [0, 0x83 << 1, 0x1b << 1] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume(&storage, &arena, &time);
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        SCRIPT.with_borrow_mut(|s| {
            s.poll.push_back((0, false));
            s.status.push_back(status);
        });
        time.set(21);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.authority_report().state, State::Serving);
        assert_eq!(volume.table_report().abandoned, 1);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.table_report().abandoned, 0);
        assert_eq!(
            volume.authority_report().state,
            if status == 0 {
                State::Serving
            } else {
                State::Withdrawn
            }
        );
        assert_eq!(
            volume.authority_report().report_age_us,
            if status == 0 { Some(21) } else { None }
        );
        if status != 0 {
            assert_eq!(
                volume.authority_report().refusal,
                Some(if status == 0x83 << 1 {
                    crate::storage::AuthorityRefusal::Conflict
                } else {
                    crate::storage::AuthorityRefusal::PreemptAborted
                })
            );
        }
        volume.close();
    }
}

#[test]
fn report_holder_classification_distinguishes_zero_foreign_and_malformed() {
    use crate::failover::serving::State;
    for (epoch, expected_state, expected_refusal) in [
        (0, State::Withdrawn, None),
        (
            1,
            State::Withdrawn,
            Some(crate::storage::AuthorityRefusal::ForeignLower),
        ),
        (
            2,
            State::Withdrawn,
            Some(crate::storage::AuthorityRefusal::ForeignEqual),
        ),
        (
            3,
            State::Withdrawn,
            Some(crate::storage::AuthorityRefusal::ForeignHigher),
        ),
        (
            u64::MAX,
            State::Withdrawn,
            Some(crate::storage::AuthorityRefusal::ReportMalformed),
        ),
    ] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume(&storage, &arena, &time);
        let mut bytes = report(if epoch == 0 { 0 } else { 1 });
        if epoch == 0 {
            bytes[4] = 0;
        } else if epoch == u64::MAX {
            bytes[4] = 1;
            bytes[72..80].copy_from_slice(&key(2).encode().to_le_bytes());
        } else {
            bytes[64..66].copy_from_slice(&11u16.to_le_bytes());
            bytes[72..80].copy_from_slice(&key(epoch).encode().to_le_bytes());
            bytes[80..96].fill(2);
        }
        SCRIPT.with_borrow_mut(|s| s.report_bytes = bytes);
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        volume.poll_storage(0, &mut out);
        let report = volume.authority_report();
        assert_eq!(report.state, expected_state);
        if let Some(cause) = expected_refusal {
            assert_eq!(report.refusal, Some(cause));
        }
        // NO-HOLDER-HOLD: an empty Report with no reservation shows nobody holding beside no other registrant, so
        // it withdraws with no flip request; every other row retires with the flip naming the own tenure.
        if epoch == 0 {
            assert_eq!(
                (report.withdrawal, report.flip),
                (Some(crate::failover::serving::Cause::Unheld), None),
                "epoch {epoch}"
            );
        } else {
            let trigger = if epoch == u64::MAX {
                crate::failover::evidence::NotSole::ReservationType
            } else {
                crate::failover::evidence::NotSole::ForeignHolder
            };
            assert_eq!(
                report.withdrawal,
                crate::failover::serving::ReportTrigger::new(trigger)
                    .map(crate::failover::serving::Cause::Report),
                "epoch {epoch}"
            );
            assert_eq!(
                report.flip.map(|flip| (flip.generation, flip.attempts)),
                Some((report.tenure.0, report.tenure.1.get() / 2)),
                "epoch {epoch}: the flip names the own tenure"
            );
        }
        let submitted = volume.report().metadata_submitted;
        for _ in 0..4 {
            volume.poll_storage(0, &mut out);
        }
        assert_eq!(volume.report().metadata_submitted, submitted);
        volume.close();
    }
}

#[test]
fn persisted_key_admits_acquire_and_preempt_while_foreign_keys_refuse() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink, DmaRange};
    let authority = crate::bind::authority_tests::prepared();
    let pair = authority.pair();
    SCRIPT.take();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:authority-acquire",
        limits(8),
        &mut registration,
    );
    disk.set_authority(authority);
    disk.set_reservation_limits(bounds());
    let mut buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    disk.mark_verified(buffer.range(4096).unwrap());
    let other_host = Pair {
        exhid: Exhid::new([4; 16]).unwrap(),
        ..pair
    };
    for (current, preempt) in [
        (
            key(1),
            Pair {
                key: key(1),
                ..pair
            },
        ),
        (pair.key, other_host),
        (pair.key, pair),
    ] {
        for command in [
            ReservationCommand::Acquire { current },
            ReservationCommand::PreemptAndAbort(self_preempt(preempt)),
            ReservationCommand::PreemptLineage(lineage_preempt(
                preempt,
                Pair {
                    exhid: Exhid::new([5; 16]).unwrap(),
                    key: key(1),
                },
            )),
            ReservationCommand::PreemptEnded(ended_preempt(preempt)),
        ] {
            let admitted = match command {
                ReservationCommand::PreemptAndAbort(own) => own.pair() == pair,
                ReservationCommand::PreemptLineage(lineage) => lineage.pair() == pair,
                ReservationCommand::PreemptEnded(ended) => ended.pair() == pair,
                _ => current == pair.key,
            };
            command.encode(&mut buffer.bytes_mut()[..16]);
            let memory = DmaRange::new(buffer.range(4096).unwrap().addr(), buffer.offset(), 16);
            let before = SCRIPT.with_borrow(|s| s.reservation_calls.len());
            // SAFETY: the buffer remains exclusive until refusal or the terminal picked below.
            let result =
                unsafe { disk.submit_reservation(CommandToken::from_raw(1), command, memory) };
            if admitted {
                result.unwrap();
                let mut out = Vec::with_capacity(1);
                disk.pick_completions(&mut CompletionSink::new(&mut out, 1));
                assert_eq!(out.len(), 1);
                assert_eq!(
                    SCRIPT.with_borrow(|s| s.reservation_calls.len()),
                    before + 1
                );
            } else {
                assert_eq!(result.unwrap_err().reason, RefusalReason::NotVerified);
                assert_eq!(SCRIPT.with_borrow(|s| s.reservation_calls.len()), before);
            }
        }
    }
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}

#[test]
fn an_adverse_report_withdraws_after_a_renewed_window() {
    use crate::failover::serving::{Event, OwnReport, State};
    for foreign in [false, true] {
        let arena = arena_with_len(16384);
        let mut storage =
            crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
        storage.read_commands = 4;
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut volume = serving_volume(&storage, &arena, &time);
        let mut bytes = report(usize::from(foreign));
        if foreign {
            bytes[64..66].copy_from_slice(&11u16.to_le_bytes());
            bytes[80..96].fill(2);
        } else {
            bytes[4] = 0;
        }
        SCRIPT.with_borrow_mut(|s| s.report_bytes = bytes);
        let mut out = Vec::with_capacity(16);
        time.set(10);
        volume.poll_storage(0, &mut out);
        volume.authority_event(Event::Expire { now: 10 });
        time.set(11);
        volume.authority_event(Event::OwnHolder(OwnReport {
            pair: Pair {
                key: key(2),
                ..dummy().pair
            },
            lineage: 1,
            submitted_at: 11,
            certified_at: 11,
        }));
        assert_eq!(volume.authority_report().state, State::Serving);
        volume.poll_storage(0, &mut out);
        assert_eq!(volume.authority_report().state, State::Withdrawn);
        volume.close();
    }
}

/// Attach confirms the host ID by Get Features before it allocates the I/O qpair, so before any reservation
/// command. A success status with any phase, retry-delay, more or do-not-retry bits that reads the connected host
/// ID admits the attach. Another host ID refuses with `HostIdMismatch`. An error status, a refused submit, a failed
/// admin poll, including one that ran the callback, and a command still outstanding at the admin timeout each
/// refuse with `HostIdUnconfirmed` and the corresponding `HostIdFailure`. Every refusal detaches the controller
/// before qpair allocation and reservation commands and releases the address; a refused detach keeps it reserved.
#[test]
fn host_id_confirmed_before_reservation_command() {
    use super::super::disk::Disk;
    use super::super::identify_tests::SERIAL;
    use super::attach_tests::{configure_with, script};
    use super::disk::{HostIdFailure, SpdkAttachError, SpdkConfig};
    use crate::native::{Environment, registration_tests};
    #[derive(Clone, Copy)]
    struct Case {
        name: &'static str,
        host_id: [u8; 16],
        status: u16,
        rc: i32,
        held: bool,
        admin_rc: Option<i32>,
        detach_rc: i32,
        inline: bool,
        timeout_us: u64,
        expected: Result<(), SpdkAttachError>,
    }
    let confirmed = Case {
        name: "confirmed",
        host_id: *b"persisted-exhid!",
        status: 0,
        rc: 0,
        held: false,
        admin_rc: None,
        detach_rc: 0,
        inline: false,
        timeout_us: 1_000,
        expected: Ok(()),
    };
    let unconfirmed = |failure| Err(SpdkAttachError::HostIdUnconfirmed(failure));
    for case in [
        confirmed,
        Case {
            name: "phase",
            status: 0x0001,
            ..confirmed
        },
        Case {
            name: "flags",
            status: 0xF001,
            ..confirmed
        },
        Case {
            name: "other",
            host_id: *b"another-host-id!",
            expected: Err(SpdkAttachError::HostIdMismatch),
            ..confirmed
        },
        Case {
            name: "failed",
            status: 0x2 << 1,
            expected: unconfirmed(HostIdFailure::Status(0x2 << 1)),
            ..confirmed
        },
        Case {
            name: "type",
            status: 1 << 9,
            expected: unconfirmed(HostIdFailure::Status(1 << 9)),
            ..confirmed
        },
        Case {
            name: "refused",
            rc: -12,
            expected: unconfirmed(HostIdFailure::Submit(-12)),
            ..confirmed
        },
        Case {
            name: "poll-failed",
            held: true,
            admin_rc: Some(-6),
            expected: unconfirmed(HostIdFailure::Poll(-6)),
            ..confirmed
        },
        Case {
            name: "poll-failed-after-completion",
            admin_rc: Some(-6),
            expected: unconfirmed(HostIdFailure::Poll(-6)),
            ..confirmed
        },
        Case {
            name: "outstanding",
            held: true,
            expected: unconfirmed(HostIdFailure::Timeout),
            ..confirmed
        },
        Case {
            name: "zero-timeout",
            timeout_us: 0,
            ..confirmed
        },
        Case {
            name: "zero-timeout-outstanding",
            held: true,
            timeout_us: 0,
            expected: unconfirmed(HostIdFailure::Timeout),
            ..confirmed
        },
        Case {
            name: "inline",
            inline: true,
            ..confirmed
        },
        Case {
            name: "outstanding-detach-refused",
            held: true,
            detach_rc: -16,
            expected: unconfirmed(HostIdFailure::Timeout),
            ..confirmed
        },
    ] {
        let name = case.name;
        SCRIPT.take();
        let bdf = format!("scripted:host-id-{name}");
        script(&bdf, SERIAL, 9);
        SCRIPT.with_borrow_mut(|s| {
            s.feature_host_id = case.host_id;
            s.feature_status = case.status;
            s.feature_rc = case.rc;
            s.feature_held = case.held;
            s.admin_rc.extend(case.admin_rc);
            s.detach.push_back(case.detach_rc);
            s.submit_inline = case.inline;
        });
        let (env, arena) = (Environment::detached(), registration_tests::new_arena());
        let mut registration = registration_tests::ready(&env, &arena);
        let config = SpdkConfig {
            queue_depth: 8,
            timeout_io_us: 1_000_000,
            timeout_admin_us: case.timeout_us,
        };
        let limits = crate::storage::ReservationLimits::new(2, 2, 10, 10).unwrap();
        let seen = || super::disk_tests::calls();
        match configure_with(&bdf, &mut registration, config, limits) {
            Ok(mut disk) => {
                assert_eq!(case.expected, Ok(()), "{name}");
                let calls = seen();
                let at = |call| calls.iter().position(|&c| c == call).unwrap();
                assert!(
                    at(Call::GetFeature) < at(Call::AllocQpair),
                    "{name}: {calls:?}"
                );
                assert_eq!(
                    calls.iter().filter(|&&call| call == Call::Admin).count(),
                    1,
                    "{name}: one admin poll observes the completion"
                );
                assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
                assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
                registration
                    .device_stopped(disk.stop_proof().unwrap())
                    .unwrap();
                assert!(disk.detach(&registration_tests::undone(registration)));
            }
            Err(error) => {
                assert_eq!(Err(error), case.expected, "{name}");
                let calls = seen();
                assert!(
                    calls.contains(&Call::GetFeature)
                        && !calls.contains(&Call::AllocQpair)
                        && calls.last() == Some(&Call::Detach),
                    "{name}: {calls:?}"
                );
                if case.admin_rc.is_some() {
                    assert_eq!(
                        calls.iter().filter(|&&call| call == Call::Admin).count(),
                        1,
                        "{name}: a failed admin poll ends the wait"
                    );
                }
                assert!(
                    SCRIPT.with_borrow(|s| s.reservation_calls.is_empty()),
                    "{name}"
                );
                assert_eq!(
                    super::disk::attached().contains(&bdf),
                    case.detach_rc != 0,
                    "{name}: a detached controller releases the address"
                );
                assert_eq!(
                    SCRIPT.with_borrow(|s| s.features.len()),
                    usize::from(case.held && case.detach_rc != 0),
                    "{name}: a refused detach leaves the held Get Features outstanding"
                );
            }
        }
        super::disk::attached().remove(&bdf);
    }
}

/// An authority disk's medium gate opens at the volume's gate pass and only then. The attached driver, an admission
/// before the reservation gate and the reservation gate alone each leave `medium_withheld` set and refuse a read, a
/// write and the canary `NotVerified` with no device call; after both, the flag clears, a read and a write over the
/// verified range reach the device and complete, and a read or write of a buffer past that range refuses
/// `InvalidRange` with no device call.
#[test]
fn medium_admission_opens_an_authority_disk_after_the_reservation_gate_alone() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink, DmaRange};
    SCRIPT.take();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:medium-admission",
        limits(8),
        &mut registration,
    );
    disk.set_authority(crate::bind::authority_tests::prepared());
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let memory = buffer.range(4096).unwrap();
    let submit = |disk: &mut SpdkDisk<'_, Scripted>, write: bool, token: u64, memory: DmaRange| {
        let device = DeviceRange::new(0, memory.byte_len()).unwrap();
        // SAFETY: a refused command keeps the exclusive buffer with the caller, and an admitted one holds it until
        // its terminal is picked below.
        unsafe {
            if write {
                disk.submit_write(CommandToken::from_raw(token), device, memory)
            } else {
                disk.submit_read(CommandToken::from_raw(token), device, memory)
            }
        }
    };
    let gate = crate::storage::Fenced::assumed_for(crate::bind::authority_tests::prepared().pair());
    let closed = |disk: &mut SpdkDisk<'_, Scripted>,
                  registration: &crate::native::ArenaRegistration<'_>,
                  arena: &BufferArena<TestPlatform>,
                  step: &str| {
        assert!(disk.medium_withheld(), "{step}: the authority withholds");
        for write in [false, true] {
            assert_eq!(
                submit(disk, write, 41, memory).unwrap_err().reason,
                RefusalReason::NotVerified,
                "{step}"
            );
        }
        let canary = arena.acquire(PoolKind::ReceiveWrite).unwrap();
        match disk.canary(registration, canary, std::time::Duration::from_secs(1)) {
            Err(super::disk::CanaryError::Refused(refusal)) => {
                assert_eq!(refusal.reason, RefusalReason::NotVerified, "{step}")
            }
            other => panic!("{step}: the canary under an authority refuses, got {other:?}"),
        }
        assert!(
            super::disk_tests::calls().is_empty(),
            "{step}: no refused command reaches the device"
        );
    };
    closed(&mut disk, &registration, &arena, "attached");
    disk.admit_medium(&gate);
    closed(
        &mut disk,
        &registration,
        &arena,
        "admitted before the reservation gate",
    );
    disk.enable_reservations(&registration).unwrap();
    closed(&mut disk, &registration, &arena, "reservation gate alone");
    disk.admit_medium(&crate::storage::Fenced::assumed_for(
        crate::storage::gate_fixture::foreign(),
    ));
    closed(
        &mut disk,
        &registration,
        &arena,
        "a gate value for another pair",
    );
    disk.admit_medium(&gate);
    assert!(!disk.medium_withheld(), "the gate pass admits");
    let second = arena.acquire(PoolKind::ReadResponse).unwrap();
    submit(&mut disk, false, 42, memory).unwrap();
    submit(&mut disk, true, 43, second.range(4096).unwrap()).unwrap();
    let mut done = Vec::with_capacity(2);
    while done.len() < 2 {
        disk.pick_completions(&mut CompletionSink::new(&mut done, 2));
    }
    let submits = || {
        super::disk_tests::calls()
            .iter()
            .filter(|call| **call == super::disk_tests::Call::Submit)
            .count()
    };
    assert_eq!(submits(), 2, "the admitted read and write reach the device");
    // A range at the extent's base whose last 4 KiB lie past the verified extent, with a device range of the same
    // length so only the extent clause refuses it; the address is never read.
    let (base, extent) = registration.range();
    let past = DmaRange::new(
        std::ptr::NonNull::new(std::ptr::without_provenance_mut(base + extent - 4096)).unwrap(),
        extent - 4096,
        8192,
    );
    for write in [false, true] {
        assert_eq!(
            submit(&mut disk, write, 44, past).unwrap_err().reason,
            RefusalReason::InvalidRange,
            "a buffer past the installed range refuses"
        );
    }
    assert_eq!(submits(), 2, "the refused range reaches no device call");
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}

/// An owner's SPDK driver and ENA port share one arena registration (`native/dataplane.rs`), and the port's recovery
/// rechecks it before a restart. A failed recheck leaves the registration unverified, and readiness is the
/// precondition for any arena command ([`is_ready`](crate::native::ArenaRegistration::is_ready)). Before the
/// recheck a read over the admitted range reaches the device and completes; after it, no read, write or Register
/// over the arena reaches the device, and each refuses `NotVerified`.
#[test]
fn a_failed_recheck_of_the_shared_registration_closes_the_arena_to_the_driver() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::Disk;
    use crate::storage::device::disk::{CommandToken, CompletionSink, DmaRange};
    SCRIPT.take();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let (mut registration, remap) = registration_tests::ready_until_stale(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:stale-registration",
        limits(8),
        &mut registration,
    );
    let authority = crate::bind::authority_tests::prepared();
    let pair = authority.pair();
    let gate = crate::storage::Fenced::assumed_for(pair);
    disk.set_reservation_limits(bounds());
    disk.set_authority(authority);
    disk.enable_reservations(&registration).unwrap();
    disk.admit_medium(&gate);
    let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
    let memory = buffer.range(4096).unwrap();
    let submit = |disk: &mut SpdkDisk<'_, Scripted>, write: bool, token: u64, memory: DmaRange| {
        let device = DeviceRange::new(0, memory.byte_len()).unwrap();
        // SAFETY: a refused command keeps the exclusive buffer with the caller, and an admitted one holds it until
        // its terminal is picked below.
        unsafe {
            if write {
                disk.submit_write(CommandToken::from_raw(token), device, memory)
            } else {
                disk.submit_read(CommandToken::from_raw(token), device, memory)
            }
        }
    };
    let submits = || {
        super::disk_tests::calls()
            .iter()
            .filter(|call| **call == Call::Submit)
            .count()
    };
    submit(&mut disk, false, 41, memory).unwrap();
    let mut done = Vec::with_capacity(1);
    while done.is_empty() {
        disk.pick_completions(&mut CompletionSink::new(&mut done, 1));
    }
    assert_eq!(
        submits(),
        1,
        "a read over the verified registration reaches the device"
    );
    remap();
    assert!(registration.recheck().is_err());
    assert!(
        !registration.is_ready(),
        "the failed recheck revokes readiness"
    );
    for (write, token) in [(false, 42), (true, 43)] {
        assert_eq!(
            submit(&mut disk, write, token, memory).map_err(|refusal| refusal.reason),
            Err(RefusalReason::NotVerified),
            "a {} over the unverified registration refuses",
            if write { "write" } else { "read" }
        );
    }
    let mut reservation = arena.acquire(PoolKind::ReadResponse).unwrap();
    let command = ReservationCommand::Register { new: pair.key };
    command.encode(&mut reservation.bytes_mut()[..16]);
    let payload = DmaRange::new(
        reservation.range(4096).unwrap().addr(),
        reservation.offset(),
        16,
    );
    // SAFETY: the exclusive live buffer covers the 16-byte payload, and a refusal retains nothing.
    let refused = unsafe { disk.submit_reservation(CommandToken::from_raw(44), command, payload) };
    assert_eq!(
        refused.map_err(|refusal| refusal.reason),
        Err(RefusalReason::NotVerified),
        "a reservation command over the unverified registration refuses"
    );
    assert_eq!(
        submits(),
        1,
        "no command over the unverified registration reaches the device"
    );
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Pending);
    assert_eq!(disk.quiesce(), crate::storage::QuiesceStatus::Stopped);
    registration
        .device_stopped(disk.stop_proof().unwrap())
        .unwrap();
    assert!(disk.detach(&registration_tests::undone(registration)));
}

/// A volume over an authority-attached scripted driver passes its gate on the device's own Register, Acquire and
/// Report, opens the driver's medium gate from that pass alone, and reaches `Open`: no medium command reaches the
/// device before the gate's Report, and the bootstrap's root probes and RESET writes follow it. Nothing outside the
/// volume calls `admit_medium`.
#[test]
fn a_volume_over_an_authority_disk_opens_through_its_own_gate_pass() {
    use crate::native::{Environment, registration_tests};
    SCRIPT.take();
    let authority = crate::bind::authority_tests::prepared();
    let pair = authority.pair();
    // The device's Report shows the own pair as sole holder and registrant.
    let mut own = report(1);
    own[64 + 8..64 + 16].copy_from_slice(&pair.key.encode().to_le_bytes());
    own[64 + 16..64 + 32].copy_from_slice(&pair.exhid.bytes());
    SCRIPT.with_borrow_mut(|s| s.report_bytes = own);
    let storage = crate::storage::owner_fixture::hardware_storage_on(512 << 10, 3 * 16384, 64);
    let arena = arena_with_len(16384);
    let env = Environment::detached();
    let mut registration = registration_tests::ready(&env, &arena);
    let mut disk = SpdkDisk::<Scripted>::scripted_leased(
        "scripted:authority-volume",
        limits(8),
        &mut registration,
    );
    disk.set_authority(authority);
    disk.set_reservation_limits(bounds());
    disk.enable_reservations(&registration).unwrap();
    disk.set_facts(crate::storage::volume_fixture::facts_for(
        1 << 30,
        128 << 10,
    ));
    assert!(disk.medium_withheld());
    let serving = crate::storage::ServingAuthority::fixture_pair_under(
        bounds(),
        crate::storage::next_session(),
        pair,
    );
    let mut volume = crate::storage::Volume::attach(
        &storage,
        &arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        serving,
        8,
        crate::storage::TickConfig {
            submit_burst: 1,
            ..crate::storage::volume_fixture::TICK
        },
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    crate::storage::volume_fixture::open_polled(&mut volume, 256);
    // Every reservation command logs its kind and then `Submit`; a medium command logs `Submit` alone.
    let calls = super::disk_tests::calls();
    let reservation = |at: usize| {
        at > 0 && matches!(calls[at - 1], Call::Register | Call::Acquire | Call::Report)
    };
    let medium: Vec<usize> = (0..calls.len())
        .filter(|&at| calls[at] == Call::Submit && !reservation(at))
        .collect();
    let report = calls
        .iter()
        .position(|call| *call == Call::Report)
        .expect("the gate's Report");
    assert!(
        medium.len() >= 4 && medium.iter().all(|&at| at > report),
        "the root probes and RESET writes follow the gate's Report: {calls:?}"
    );
    assert_eq!(
        calls.iter().filter(|call| **call == Call::Register).count(),
        1,
        "one gate sequence"
    );
    volume.close();
}

/// A lineage preempt resolves only a type-2 reservation held by one recorded pair in the admitted holder set, other
/// than the own pair, with every other registrant the own pair or recorded, and names that holder's key as PRKEY;
/// the own pair holding, an unrecorded holder, a recorded holder outside the admitted set, nobody holding, a
/// reservation of another type and an unrecorded registrant each refuse in check order.
#[test]
fn a_lineage_preempt_names_only_a_recorded_holder_other_than_the_own_pair() {
    use crate::storage::{HolderRefusal, LineagePreempt};
    let own = scripted_pair(key(2));
    let predecessor = Pair {
        exhid: Exhid::new([3; 16]).unwrap(),
        key: key(3),
    };
    let stranger = Pair {
        exhid: Exhid::new([4; 16]).unwrap(),
        key: key(4),
    };
    let resolve = |rtype: u8, entries: &[(Pair, bool)], recorded: &[Pair], live: &[Pair]| {
        let entries: Vec<Registrant> = entries
            .iter()
            .enumerate()
            .map(|(at, &(pair, holder))| Registrant {
                cntlid: at as u16 + 1,
                holder,
                pair,
            })
            .collect();
        let report = crate::failover::evidence::Report {
            submitted_at: 0,
            rtype: if rtype == 2 {
                ReservationType::ExclusiveAccess
            } else {
                ReservationType::None
            },
            regctl: entries.len() as u32,
            entries: &entries,
        };
        LineagePreempt::resolve(&report, recorded, live, own, &preempt_bounds())
    };
    let resolved = resolve(
        2,
        &[(predecessor, true), (own, false)],
        &[predecessor, own],
        &[predecessor, own],
    )
    .unwrap();
    assert_eq!(
        (resolved.pair(), resolved.preempted()),
        (own, predecessor.key)
    );
    let unregistered = resolve(2, &[(predecessor, true)], &[predecessor], &[predecessor]).unwrap();
    assert_eq!(unregistered.preempted(), predecessor.key);
    assert_eq!(
        resolve(
            2,
            &[(own, true), (predecessor, false)],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Own)
    );
    assert_eq!(
        resolve(
            2,
            &[(stranger, true), (own, false)],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Unrecorded)
    );
    assert_eq!(
        resolve(
            2,
            &[(predecessor, false), (own, false)],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Unresolved)
    );
    assert_eq!(
        resolve(
            0,
            &[(predecessor, true), (own, false)],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Unresolved)
    );
    assert_eq!(
        resolve(
            2,
            &[(predecessor, true), (stranger, false), (own, false)],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Registrants(NotSole::ForeignRegistrant))
    );
    assert_eq!(
        resolve(
            2,
            &[
                (predecessor, true),
                (own, false),
                (Pair { key: key(5), ..own }, false)
            ],
            &[predecessor],
            &[predecessor]
        ),
        Err(HolderRefusal::Registrants(NotSole::DuplicateOwnRecord))
    );
    assert_eq!(
        resolve(2, &[(predecessor, true), (own, false)], &[predecessor], &[]),
        Err(HolderRefusal::NotAdmitted),
        "a holder recorded for an ended attach is outside the live attachments"
    );
}

/// NO-HOLDER-HOLD's test accepts a conclusive Report in which nobody holds, by no holding entry or no reservation,
/// with every registrant the own pair or recorded and at most one own record under the own key, an empty Report
/// included. A holder, an unrecorded registrant, a second own record, the own host ID under another key and an
/// inconclusive count each refuse the hold. The own pair listed twice, and the own host ID under a key the recorded
/// set holds, refuse on the own-record count alone, since every entry is the own pair or recorded.
#[test]
fn the_no_holder_hold_needs_nobody_holding_beside_recorded_registrants() {
    let (own, predecessor, stranger) = hold_pairs();
    let alias = Pair { key: key(5), ..own };
    let recorded: &[Pair] = &[predecessor];
    let exclusive = ReservationType::ExclusiveAccess;
    let none = ReservationType::None;
    for (rtype, entries) in [
        (exclusive, vec![(own, false), (predecessor, false)]),
        (exclusive, vec![(predecessor, false)]),
        (none, vec![(own, false), (predecessor, false)]),
        (none, vec![]),
    ] {
        assert!(
            unheld_under(own, recorded, rtype, &entries, None),
            "{rtype:?} {entries:?}"
        );
    }
    for (rtype, entries, regctl) in [
        (exclusive, vec![(own, true), (predecessor, false)], None),
        (exclusive, vec![(predecessor, true), (own, false)], None),
        (exclusive, vec![(own, false), (stranger, false)], None),
        (none, vec![(stranger, false)], None),
        (exclusive, vec![(own, false), (alias, false)], None),
        (exclusive, vec![(alias, false)], None),
        (exclusive, vec![(own, false)], Some(2)),
        (exclusive, vec![(own, false), (own, false)], None),
        (none, vec![(own, false), (own, false)], None),
    ] {
        refuses_the_hold(own, recorded, rtype, &entries, regctl);
    }
    for rtype in [exclusive, none] {
        refuses_the_hold(
            own,
            &[predecessor, alias],
            rtype,
            &[(own, false), (alias, false)],
            None,
        );
    }
}

/// The planted record: the stranger's pair joins the recorded set, so the Report in which the own pair and the
/// stranger register and nobody holds counts no unrecorded registrant and holds, as one judged without its census of
/// unrecorded registrants would, and the hold's refusal check rejects it.
#[test]
#[should_panic(expected = "the no-holder hold refuses ExclusiveAccess")]
fn negative_control_a_recorded_stranger_lets_the_report_hold() {
    let (own, predecessor, stranger) = hold_pairs();
    refuses_the_hold(
        own,
        &[predecessor, stranger],
        ReservationType::ExclusiveAccess,
        &[(own, false), (stranger, false)],
        None,
    );
}

/// The own pair under the scripted driver's host ID, a recorded predecessor and an unrecorded stranger, each under
/// its own host ID and key.
fn hold_pairs() -> (Pair, Pair, Pair) {
    let predecessor = Pair {
        exhid: Exhid::new([3; 16]).unwrap(),
        key: key(3),
    };
    let stranger = Pair {
        exhid: Exhid::new([4; 16]).unwrap(),
        key: key(4),
    };
    (scripted_pair(key(2)), predecessor, stranger)
}

/// Whether the no-holder hold accepts a Report of `rtype` listing `entries`, each a pair and whether it holds, for
/// `own` beside the `recorded` pairs; `regctl` replaces the registrant count the Report states, which is otherwise
/// the entry count.
fn unheld_under(
    own: Pair,
    recorded: &[Pair],
    rtype: ReservationType,
    entries: &[(Pair, bool)],
    regctl: Option<u32>,
) -> bool {
    let entries: Vec<Registrant> = entries
        .iter()
        .enumerate()
        .map(|(at, &(pair, holder))| Registrant {
            cntlid: at as u16 + 1,
            holder,
            pair,
        })
        .collect();
    let report = crate::failover::evidence::Report {
        submitted_at: 0,
        rtype,
        regctl: regctl.unwrap_or(entries.len() as u32),
        entries: &entries,
    };
    let census = report.census(own, |pair| recorded.contains(pair));
    crate::storage::unheld_among_recorded(&report, &census, own, &preempt_bounds())
}

/// Asserts that the no-holder hold refuses the Report [`unheld_under`] builds from the same arguments.
fn refuses_the_hold(
    own: Pair,
    recorded: &[Pair],
    rtype: ReservationType,
    entries: &[(Pair, bool)],
    regctl: Option<u32>,
) {
    assert!(
        !unheld_under(own, recorded, rtype, entries, regctl),
        "the no-holder hold refuses {rtype:?} {entries:?} {regctl:?} beside {recorded:?}"
    );
}
