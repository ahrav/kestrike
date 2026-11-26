//! Each Report applies the own-record validation, and a second record with the own host ID, or the own host ID
//! under another key, withholds the Report's bytes; an absent own entry passes.
//!
//! The scenario completes reservation Reports with a successful status through a `CommandTable`. Its driver
//! runs the crate's own check, `check_report_identity`, with its attachment pair, as the SPDK driver does, over
//! the bytes the device left in the table's reservation buffer. Each test reads the terminal's `report_error`
//! and then asks the table for the Report's bytes with `CommandTable::reservation_report(token)`.
//!
//! Every verdict is decided into a value, the table and the arena are let go, and only then does the test
//! assert, so a failure ends in the test's own result line.

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::{
    BufferArena, BufferConfig, Classification, CommandTable, CommandToken, Completion,
    CompletionSink, DeviceGeometry, DeviceRange, DeviceStatus, Disk, DmaRange, PoolKind, PoolSpec,
    QuiesceStatus, ReportError, ReservationCommand, ReservationLimits, SubmitRefusal, Terminal,
    check_report_identity,
};
use crate::failover::evidence::Pair;
use crate::failover::identity::{Exhid, Key};

/// The host ID of the driver's own attachment, as every byte of the Report row's host field.
const OWN_HOST: u8 = 1;
/// A host ID no attachment of the driver carries.
const OTHER_HOST: u8 = 5;

fn key(n: u64) -> Key {
    Key::decode((n << 32) | n).expect("a valid key")
}

/// The driver's attachment pair: the own host ID under key 1.
fn own() -> Pair {
    Pair {
        exhid: Exhid::new([OWN_HOST; 16]).expect("a nonzero host ID"),
        key: key(1),
    }
}

/// Three registrants a Report, two reservation commands outstanding at most.
fn limits() -> ReservationLimits {
    ReservationLimits::new(3, 2, 10, 20).expect("valid limits")
}

/// An extended Report's bytes under reservation type 2: the 64-byte header with the registrant count, then one
/// 64-byte row for each `(host, key, holder)`.
fn report(rows: &[(u8, Key, bool)]) -> Vec<u8> {
    let mut bytes = vec![0; 64 + 64 * rows.len()];
    bytes[4] = 2;
    bytes[5..7].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    for (n, &(host, key, holder)) in rows.iter().enumerate() {
        let row = &mut bytes[64 + 64 * n..64 + 64 * (n + 1)];
        row[..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        row[2] = u8::from(holder);
        row[8..16].copy_from_slice(&key.encode().to_le_bytes());
        row[16..32].fill(host);
    }
    bytes
}

/// A device that answers each Report at once with the next scripted payload and a successful status, under a
/// driver that checks a Report's identity as the SPDK driver does: `check_report_identity` with its validated
/// limits and its own pair.
struct Reporting {
    payloads: std::collections::VecDeque<Vec<u8>>,
    done: Vec<Completion>,
}

// SAFETY: the driver accepts only Reports. It writes at most `memory.byte_len()` bytes into the memory the
// accepted command owns, inside `submit_reservation`, before it queues the command's one completion; it keeps
// no pointer afterwards and reports each accepted token once, through `pick_completions`.
unsafe impl Disk for Reporting {
    fn geometry(&self) -> DeviceGeometry {
        DeviceGeometry {
            capacity: 1 << 20,
            max_transfer: 4096,
            block_size: 4096,
            queue_depth: 4,
        }
    }

    unsafe fn submit_read(
        &mut self,
        _: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        unreachable!("the scenario submits no data command")
    }

    unsafe fn submit_write(
        &mut self,
        _: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        unreachable!("the scenario submits no data command")
    }

    fn reservation_limits(&self) -> Option<ReservationLimits> {
        Some(limits())
    }

    fn check_reservation_report(&self, bytes: &[u8]) -> Result<(), ReportError> {
        check_report_identity(bytes, limits(), own())
    }

    unsafe fn submit_reservation(
        &mut self,
        token: CommandToken,
        command: ReservationCommand,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        assert!(command.is_report(), "the scenario submits Reports alone");
        let len = memory.byte_len() as usize;
        let mut payload = self
            .payloads
            .pop_front()
            .expect("one scripted payload for each Report");
        assert!(payload.len() <= len, "the payload fits the Report's memory");
        payload.resize(len, 0);
        // SAFETY: the table handed this command `len` writable bytes at `memory.addr()` and holds no reference
        // into them until the command's terminal; `payload` is a separate heap allocation of `len` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), memory.addr().as_ptr(), len);
        }
        self.done.push(Completion {
            token,
            status: DeviceStatus::Nvme(0),
        });
        Ok(())
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        while let Some(done) = self.done.pop() {
            if let Err(refused) = sink.push(done) {
                self.done.push(refused);
                break;
            }
        }
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        QuiesceStatus::Pending
    }
}

/// What one completed Report left behind.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// The poll delivered exactly this Report's terminal, a `Terminal::Reservation` under its token whose
    /// status classifies as success for the Report's length.
    succeeded: bool,
    /// The identity refusal the terminal carries.
    report_error: Option<ReportError>,
    /// The bytes `CommandTable::reservation_report` hands out for the Report's token, read right after its
    /// terminal and before the next submission.
    readable: Option<Vec<u8>>,
}

/// Completes one Report for each of `payloads`, in order, through one command table over [`Reporting`], and
/// returns what each left, with whether the arena took every buffer back once the table was gone.
fn reports_through_a_table(payloads: &[Vec<u8>]) -> (Vec<Seen>, bool) {
    let pools = [
        PoolKind::ReadResponse,
        PoolKind::ReceiveWrite,
        PoolKind::Maintenance,
        PoolKind::Reservation,
    ]
    .map(|kind| PoolSpec {
        kind,
        count: if kind == PoolKind::Reservation { 2 } else { 8 },
        buffer_len: 4096,
    });
    let config = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("a valid buffer configuration");
    let arena = BufferArena::initialize(
        &config,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("a heap-backed arena");
    let disk = Reporting {
        payloads: payloads.iter().cloned().collect(),
        done: Vec::new(),
    };
    let mut table = CommandTable::new(disk, &arena, 4, &mut EngineBudget::new(usize::MAX))
        .map_err(|(error, _)| error)
        .expect("a table over a reserving driver");
    let report_bytes = limits().report_bytes();
    let mut seen = Vec::new();
    for ordinal in 0..payloads.len() as u64 {
        let token = table
            .submit_reservation(ReservationCommand::Report { not_before: 0 }, ordinal)
            .expect("an open table accepts one Report an ordinal");
        let mut out = Vec::with_capacity(4);
        let delivered = table.poll(&mut out).delivered;
        let (succeeded, report_error) = match out.as_slice() {
            [
                Terminal::Reservation {
                    token: ended,
                    status: Some(status),
                    report_error,
                },
            ] => (
                delivered == 1
                    && *ended == token
                    && status.classify(report_bytes) == Classification::Success,
                *report_error,
            ),
            _ => (false, None),
        };
        seen.push(Seen {
            succeeded,
            report_error,
            readable: table.reservation_report(token).map(<[u8]>::to_vec),
        });
    }
    drop(table);
    (seen, arena.release().is_ok())
}

/// `payload` as the table hands it out: zero-padded to the Report length of the driver's limits.
fn padded(mut payload: Vec<u8>) -> Vec<u8> {
    payload.resize(limits().report_bytes() as usize, 0);
    payload
}

/// A successful Report that shows two records with the own host ID is refused by the own-record count, its
/// terminal carries that refusal, and the table hands out none of its bytes.
#[test]
fn a_report_with_two_own_host_id_records_has_its_bytes_withheld() {
    let alias = report(&[(OWN_HOST, key(1), true), (OWN_HOST, key(2), false)]);
    let (seen, released) = reports_through_a_table(&[alias]);
    assert_eq!(
        seen,
        [Seen {
            succeeded: true,
            report_error: Some(ReportError::DuplicateOwnHostId { records: 2 }),
            readable: None,
        }]
    );
    assert!(released, "the arena took every buffer back");
}

/// A successful Report that shows the own host ID under another key is refused, its terminal carries that
/// refusal, and the table hands out none of its bytes.
#[test]
fn a_report_with_the_own_host_id_under_another_key_has_its_bytes_withheld() {
    let rekeyed = report(&[(OWN_HOST, key(3), true), (OTHER_HOST, key(4), false)]);
    let (seen, released) = reports_through_a_table(&[rekeyed]);
    assert_eq!(
        seen,
        [Seen {
            succeeded: true,
            report_error: Some(ReportError::OwnHostIdKey),
            readable: None,
        }]
    );
    assert!(released, "the arena took every buffer back");
}

/// The sibling without the fault: a Report with one own record under the own key, and one with no own record
/// at all (legal before Register), each pass the check, and the table hands out exactly the bytes the device
/// wrote, through the same call.
#[test]
fn a_report_the_check_accepts_is_read_through_the_table() {
    let sole = report(&[(OWN_HOST, key(1), true), (OTHER_HOST, key(3), false)]);
    let absent = report(&[(OTHER_HOST, key(3), true)]);
    let (seen, released) = reports_through_a_table(&[sole.clone(), absent.clone()]);
    assert_eq!(
        seen,
        [
            Seen {
                succeeded: true,
                report_error: None,
                readable: Some(padded(sole)),
            },
            Seen {
                succeeded: true,
                report_error: None,
                readable: Some(padded(absent)),
            },
        ]
    );
    assert!(released, "the arena took every buffer back");
}

/// One table, three Reports in a row: an accepted one, a refused one and an accepted one. The refusal withholds
/// only its own Report's bytes; the Reports on either side of it are read in full.
#[test]
fn a_refused_report_between_two_accepted_ones_alone_is_withheld() {
    let sole = report(&[(OWN_HOST, key(1), true)]);
    let alias = report(&[(OWN_HOST, key(1), true), (OWN_HOST, key(1), false)]);
    let joined = report(&[(OWN_HOST, key(1), true), (OTHER_HOST, key(3), false)]);
    let (seen, released) = reports_through_a_table(&[sole.clone(), alias, joined.clone()]);
    let accepted = |payload: &[u8]| Seen {
        succeeded: true,
        report_error: None,
        readable: Some(padded(payload.to_vec())),
    };
    assert_ne!(
        padded(sole.clone()),
        padded(joined.clone()),
        "premise: the two accepted Reports differ, so each read names its own Report"
    );
    assert_eq!(
        seen,
        [
            accepted(&sole),
            Seen {
                succeeded: true,
                report_error: Some(ReportError::DuplicateOwnHostId { records: 2 }),
                readable: None,
            },
            accepted(&joined),
        ]
    );
    assert!(released, "the arena took every buffer back");
}
