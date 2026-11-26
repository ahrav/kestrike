//! Tests observe syscall order through LinuxPlatform and its node-list reader.
//! Finite scripts bound calls; each case declares a ten-second deadline.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use super::*;

const DEADLINE: Duration = Duration::from_secs(10);
const FD: i32 = 43;
const REQUIRED: [&str; 21] = [
    "open-denied",
    "partial-eof",
    "partial-error",
    "first-eintr",
    "late-eintr",
    "first-eacces",
    "4096",
    "4097",
    "malformed",
    "empty",
    "close-error",
    "thp-huge-success",
    "thp-huge-missing",
    "thp-huge-present",
    "thp-huge-denied",
    "thp-huge-other-missing",
    "thp-normal-success",
    "thp-normal-missing",
    "thp-normal-present",
    "thp-normal-denied",
    "thp-normal-other-missing",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Open(Vec<u8>, i32),
    Read(i32, usize),
    Close(i32),
    Advice(usize, usize, i32),
    Access(Vec<u8>, i32),
}
#[derive(Clone)]
enum Answer {
    Value(isize, i32),
    Prefix(Vec<u8>, usize),
}
struct Script {
    pending: VecDeque<(Call, Answer)>,
    reached: Vec<Call>,
    first: usize,
    supplied: Vec<u8>,
    closed_bytes: Vec<u8>,
    before_closes: Vec<i32>,
}
thread_local! {
    static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}
struct Installed;
impl Drop for Installed {
    fn drop(&mut self) {
        SCRIPT.with(|script| *script.borrow_mut() = None);
    }
}
fn install(pending: Vec<(Call, Answer)>) -> Installed {
    SCRIPT.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Script {
            pending: pending.into(),
            reached: Vec::new(),
            first: 0,
            supplied: Vec::new(),
            closed_bytes: Vec::new(),
            before_closes: Vec::new(),
        });
    });
    Installed
}
fn next(call: impl FnOnce() -> Call, buffer: Option<&mut [u8]>) -> Option<isize> {
    SCRIPT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let script = slot.as_mut()?;
        let call = call();
        script.reached.push(call.clone());
        let (expected, answer) = script
            .pending
            .pop_front()
            .expect("syscall script exhausted");
        assert_eq!(call, expected, "ordered syscall/argument oracle");
        if let Some(buffer) = buffer {
            let address = buffer.as_ptr() as usize;
            if script.first == 0 {
                script.first = address;
            }
            assert_eq!(
                address - script.first,
                script.supplied.len(),
                "read append offset"
            );
            if let Answer::Prefix(bytes, count) = &answer {
                assert!(*count <= bytes.len() && *count <= buffer.len());
                buffer[..*count].copy_from_slice(&bytes[..*count]);
                script.supplied.extend_from_slice(&bytes[..*count]);
            }
        }
        if let Call::Close(fd) = call {
            assert_eq!(
                script.before_closes.last(),
                Some(&fd),
                "owning-buffer observation precedes close"
            );
        }
        let (value, errno) = match answer {
            Answer::Value(value, errno) => (value, errno),
            Answer::Prefix(_, count) => (count as isize, libc::EBUSY),
        };
        // SAFETY: __errno_location returns this thread's writable errno cell.
        unsafe {
            *libc::__errno_location() = errno;
        }
        Some(value)
    })
}
pub(super) fn open(path: &CStr, flags: i32) -> Option<i32> {
    next(
        || Call::Open(path.to_bytes_with_nul().to_vec(), flags),
        None,
    )
    .map(|n| n as i32)
}
pub(super) fn read(fd: i32, buffer: &mut [u8]) -> Option<isize> {
    let len = buffer.len();
    next(|| Call::Read(fd, len), Some(buffer))
}
pub(super) fn before_close(fd: i32, buffer: &[u8]) {
    SCRIPT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(script) = slot.as_mut() {
            script.before_closes.push(fd);
            script.closed_bytes = buffer.to_vec();
        }
    });
}
pub(super) fn close(fd: i32) -> Option<i32> {
    next(|| Call::Close(fd), None).map(|n| n as i32)
}
pub(super) fn advice(base: NonNull<u8>, len: usize, advice: i32) -> Option<i32> {
    next(|| Call::Advice(base.as_ptr() as usize, len, advice), None).map(|n| n as i32)
}
pub(super) fn access(path: &CStr, mode: i32) -> Option<i32> {
    next(
        || Call::Access(path.to_bytes_with_nul().to_vec(), mode),
        None,
    )
    .map(|n| n as i32)
}
fn census(expected: &[Call], prefix: &[u8], remaining: usize) {
    SCRIPT.with(|slot| {
        let slot = slot.borrow();
        let script = slot.as_ref().unwrap();
        assert_eq!(
            script.pending.len(),
            remaining,
            "close/access census: unconsumed calls"
        );
        assert_eq!(script.reached, expected, "ordered close census");
        let closed: Vec<_> = expected
            .iter()
            .filter_map(|call| match call {
                Call::Close(fd) => Some(*fd),
                _ => None,
            })
            .collect();
        assert_eq!(
            script.before_closes, closed,
            "owning-buffer observer census"
        );
        assert_eq!(script.closed_bytes, prefix, "returned-prefix byte oracle");
    });
}
fn node(name: &str) {
    let begun = Instant::now();
    let (answers, expected): (Vec<Answer>, Result<Vec<usize>, OsCode>) = match name {
        "open-denied" => (vec![], Err(OsCode(libc::EACCES))),
        "partial-eof" => (
            vec![
                Answer::Prefix(b"0-2,9junk".to_vec(), 4),
                Answer::Prefix(b"5\nBAD".to_vec(), 2),
                Answer::Value(0, libc::EBUSY),
            ],
            Ok(vec![0, 1, 2, 5]),
        ),
        "partial-error" => (
            vec![
                Answer::Prefix(b"0,9".to_vec(), 2),
                Answer::Value(-1, libc::EACCES),
            ],
            Err(OsCode(libc::EACCES)),
        ),
        "first-eintr" => (
            vec![Answer::Value(-1, libc::EINTR)],
            Err(OsCode(libc::EINTR)),
        ),
        "late-eintr" => (
            vec![
                Answer::Prefix(b"0,9".to_vec(), 2),
                Answer::Value(-1, libc::EINTR),
            ],
            Err(OsCode(libc::EINTR)),
        ),
        "first-eacces" => (
            vec![Answer::Value(-1, libc::EACCES)],
            Err(OsCode(libc::EACCES)),
        ),
        "4096" => {
            let mut bytes = b"0,".repeat(2047);
            bytes.extend_from_slice(b"1\n");
            (
                vec![Answer::Prefix(bytes, 4096), Answer::Value(0, libc::EBUSY)],
                Ok(vec![0, 1]),
            )
        }
        "4097" => {
            let mut bytes = b"0,".repeat(2047);
            bytes.extend_from_slice(b"10\n");
            assert_eq!(bytes.len(), 4097);
            assert_eq!(
                parse_node_list(&bytes).unwrap().nodes().collect::<Vec<_>>(),
                [0, 10]
            );
            assert_eq!(
                parse_node_list(&bytes[..4096])
                    .unwrap()
                    .nodes()
                    .collect::<Vec<_>>(),
                [0, 10]
            );
            (vec![Answer::Prefix(bytes, 4097)], Err(OsCode(libc::EINVAL)))
        }
        "malformed" => (
            vec![
                Answer::Prefix(b"0,,1".to_vec(), 4),
                Answer::Value(0, libc::EBUSY),
            ],
            Err(OsCode(libc::EINVAL)),
        ),
        "empty" => (vec![Answer::Value(0, libc::EBUSY)], Ok(vec![])),
        "close-error" => (
            vec![
                Answer::Prefix(b"7\nBAD".to_vec(), 2),
                Answer::Value(0, libc::EBUSY),
            ],
            Ok(vec![7]),
        ),
        _ => panic!("unknown node case {name}"),
    };
    let mut calls = vec![(
        Call::Open(
            POSSIBLE_NODES_PATH.to_bytes_with_nul().to_vec(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        ),
        Answer::Value(
            if name == "open-denied" {
                -1
            } else {
                FD as isize
            },
            libc::EACCES,
        ),
    )];
    let mut prefix = Vec::new();
    for answer in answers {
        calls.push((Call::Read(FD, 4097 - prefix.len()), answer.clone()));
        if let Answer::Prefix(bytes, count) = answer {
            prefix.extend_from_slice(&bytes[..count]);
        }
    }
    if name != "open-denied" {
        let failed_close = matches!(
            name,
            "partial-error" | "first-eintr" | "late-eintr" | "first-eacces" | "close-error"
        );
        calls.push((
            Call::Close(FD),
            Answer::Value(if failed_close { -1 } else { 0 }, libc::EBADF),
        ));
    }
    let expected_calls: Vec<_> = calls.iter().map(|(call, _)| call.clone()).collect();
    {
        let _installed = install(calls.clone());
        let observed =
            read_node_list(POSSIBLE_NODES_PATH).map(|mask| mask.nodes().collect::<Vec<_>>());
        assert_eq!(observed, expected, "node result/byte oracle: {name}");
        census(&expected_calls, &prefix, 0);
    }
    // A valid first list reaches topology's second open. Its denial fixes
    // the public outcome before the task's NUMA policy query.
    let public_expected = match expected {
        Ok(_) => {
            calls.push((
                Call::Open(
                    MEMORY_NODES_PATH.to_bytes_with_nul().to_vec(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                ),
                Answer::Value(-1, libc::EACCES),
            ));
            OsCode(libc::EACCES)
        }
        Err(code) => code,
    };
    let expected_calls: Vec<_> = calls.iter().map(|(call, _)| call.clone()).collect();
    let _installed = install(calls);
    assert_eq!(
        LinuxPlatform.topology().unwrap_err(),
        public_expected,
        "public topology: {name}"
    );
    census(&expected_calls, &prefix, 0);
    assert!(
        begun.elapsed() < DEADLINE,
        "{name}: missing deadline evidence"
    );
}
fn thp(case: &str) {
    let base = LinuxPlatform.map_inaccessible(8192).unwrap();
    for huge in [true, false] {
        for (name, madvise, access, expected) in [
            ("success", 0, None, Ok(())),
            ("missing", libc::EINVAL, Some(libc::ENOENT), Ok(())),
            ("present", libc::EINVAL, Some(0), Err(OsCode(libc::EINVAL))),
            (
                "denied",
                libc::EINVAL,
                Some(libc::EACCES),
                Err(OsCode(libc::EINVAL)),
            ),
            (
                "other-missing",
                libc::ENOMEM,
                None,
                Err(OsCode(libc::ENOMEM)),
            ),
        ] {
            let case_name = format!("thp-{}-{name}", if huge { "huge" } else { "normal" });
            if case_name != case {
                continue;
            }
            let begun = Instant::now();
            let advice = if huge {
                libc::MADV_HUGEPAGE
            } else {
                libc::MADV_NOHUGEPAGE
            };
            let mut calls = vec![(
                Call::Advice(base.as_ptr() as usize, 8192, advice),
                Answer::Value(if madvise == 0 { 0 } else { -1 }, madvise),
            )];
            if let Some(code) = access {
                calls.push((
                    Call::Access(THP_CONTROL_PATH.to_bytes_with_nul().to_vec(), libc::F_OK),
                    Answer::Value(if code == 0 { 0 } else { -1 }, code),
                ));
            }
            let expected_calls: Vec<_> = calls.iter().map(|(call, _)| call.clone()).collect();
            if access.is_none() {
                calls.push((
                    Call::Access(THP_CONTROL_PATH.to_bytes_with_nul().to_vec(), libc::F_OK),
                    Answer::Value(-1, libc::ENOENT),
                ));
            }
            let _installed = install(calls);
            // SAFETY: base names the live mapping's original base and extent.
            let observed = unsafe {
                if huge {
                    LinuxPlatform.advise_huge_pages(base, 8192)
                } else {
                    LinuxPlatform.advise_normal_pages(base, 8192)
                }
            };
            assert_eq!(observed, expected, "{huge}/{name}: original errno oracle");
            census(&expected_calls, &[], usize::from(access.is_none()));
            assert!(begun.elapsed() < DEADLINE);
        }
    }
    // SAFETY: every reference into this owned mapping has ended.
    unsafe {
        LinuxPlatform.unmap(base, 8192).unwrap();
    }
}
#[test]
fn node_open_denial_has_zero_reads_and_closes() {
    node("open-denied");
}
#[test]
fn node_partial_reads_append_only_the_returned_prefix() {
    node("partial-eof");
}
#[test]
fn node_read_error_survives_close_errno() {
    node("partial-error");
}
#[test]
fn node_first_eintr_propagates_after_one_close() {
    node("first-eintr");
}
#[test]
fn node_late_eintr_propagates_after_one_close() {
    node("late-eintr");
}
#[test]
fn node_first_eacces_propagates_after_one_close() {
    node("first-eacces");
}
#[test]
fn node_4096_bytes_are_accepted_at_eof() {
    node("4096");
}
#[test]
fn node_4097_bytes_fail_before_another_read() {
    node("4097");
}
#[test]
fn node_malformed_bytes_fail_after_one_close() {
    node("malformed");
}
#[test]
fn node_empty_eof_has_an_empty_mask() {
    node("empty");
}
#[test]
fn node_close_error_keeps_valid_read_result() {
    node("close-error");
}

#[test]
fn every_frozen_os_case_has_an_ordered_syscall_witness() {
    let mut witnessed = Vec::new();
    for name in [
        "open-denied",
        "partial-eof",
        "partial-error",
        "first-eintr",
        "late-eintr",
        "first-eacces",
        "4096",
        "4097",
        "malformed",
        "empty",
        "close-error",
        "thp-huge-success",
        "thp-huge-missing",
        "thp-huge-present",
        "thp-huge-denied",
        "thp-huge-other-missing",
        "thp-normal-success",
        "thp-normal-missing",
        "thp-normal-present",
        "thp-normal-denied",
        "thp-normal-other-missing",
    ] {
        if name.starts_with("thp-") {
            thp(name);
        } else {
            node(name);
        }
        assert!(!witnessed.contains(&name));
        witnessed.push(name);
    }
    assert_eq!(witnessed.len(), REQUIRED.len());
    for name in REQUIRED {
        assert!(witnessed.contains(&name), "missing {name}");
    }
}
#[test]
fn thp_huge_success_has_ordered_advice() {
    thp("thp-huge-success");
}
#[test]
fn thp_huge_missing_has_ordered_advice() {
    thp("thp-huge-missing");
}
#[test]
fn thp_huge_present_has_ordered_advice() {
    thp("thp-huge-present");
}
#[test]
fn thp_huge_denied_has_ordered_advice() {
    thp("thp-huge-denied");
}
#[test]
fn thp_huge_other_missing_has_ordered_advice() {
    thp("thp-huge-other-missing");
}
#[test]
fn thp_normal_success_has_ordered_advice() {
    thp("thp-normal-success");
}
#[test]
fn thp_normal_missing_has_ordered_advice() {
    thp("thp-normal-missing");
}
#[test]
fn thp_normal_present_has_ordered_advice() {
    thp("thp-normal-present");
}
#[test]
fn thp_normal_denied_has_ordered_advice() {
    thp("thp-normal-denied");
}
#[test]
fn thp_normal_other_missing_has_ordered_advice() {
    thp("thp-normal-other-missing");
}

#[test]
fn dormant_syscall_script_preserves_startup_allocation_count() {
    assert!(SCRIPT.with(|slot| slot.borrow().is_none()));
    let allocations = crate::instrument::allocations();
    let _ = LinuxPlatform.topology();
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "dormant script allocation oracle"
    );
}
