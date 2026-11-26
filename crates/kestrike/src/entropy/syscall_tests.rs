//! Syscall witnesses for complete entropy and finite interruption progress.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::EntropyError;
use crate::net::boot_nonce;

const DEADLINE: Duration = Duration::from_secs(10);
const FULL: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const REQUIRED: [&str; 32] = [
    "short-0",
    "short-1",
    "short-2",
    "short-3",
    "short-4",
    "short-5",
    "short-6",
    "short-7",
    "short-8",
    "short-9",
    "short-10",
    "short-11",
    "short-12",
    "short-13",
    "short-14",
    "short-15",
    "full",
    "zero",
    "eacces",
    "eio",
    "enosys",
    "eintr-1-full",
    "eintr-1-zero",
    "eintr-1-error",
    "eintr-3-full",
    "eintr-3-zero",
    "eintr-3-error",
    "eintr-8-full",
    "eintr-8-zero",
    "eintr-8-error",
    "eintr-short",
    "exhaustion",
];
#[derive(Clone)]
struct Answer {
    result: isize,
    errno: i32,
    prefix: Vec<u8>,
}
#[derive(Debug)]
struct Observation {
    length: usize,
    flags: u32,
    before: [u8; 16],
    result: isize,
}
struct Script {
    pending: VecDeque<Answer>,
    reached: Vec<Observation>,
}
thread_local! { static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) }; }
struct Installed;
impl Drop for Installed {
    fn drop(&mut self) {
        SCRIPT.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(super) fn draw(bytes: &mut [u8; 16], flags: u32) -> Option<isize> {
    SCRIPT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let script = slot.as_mut()?;
        let answer = script
            .pending
            .pop_front()
            .expect("entropy script exhausted");
        let before = *bytes;
        bytes[..answer.prefix.len()].copy_from_slice(&answer.prefix);
        script.reached.push(Observation {
            length: bytes.len(),
            flags,
            before,
            result: answer.result,
        });
        // SAFETY: __errno_location supplies this thread's writable errno cell.
        unsafe {
            *libc::__errno_location() = answer.errno;
        }
        Some(answer.result)
    })
}
fn run(name: &str) {
    let begun = Instant::now();
    let (interruptions, terminal, expected) = if let Some(n) = name.strip_prefix("short-") {
        let n: usize = n.parse().unwrap();
        (
            0,
            Answer {
                result: n as isize,
                errno: libc::EBUSY,
                prefix: FULL[..n].to_vec(),
            },
            Err(EntropyError::Unavailable { code: 0 }),
        )
    } else if name == "eintr-short" {
        (
            1,
            Answer {
                result: 15,
                errno: libc::EBUSY,
                prefix: FULL[..15].to_vec(),
            },
            Err(EntropyError::Unavailable { code: 0 }),
        )
    } else {
        let (k, end) = if let Some(rest) = name.strip_prefix("eintr-") {
            let (k, end) = rest.split_once('-').unwrap();
            (k.parse().unwrap(), end)
        } else {
            (0, name)
        };
        let (terminal, expected) = match end {
            "full" => (
                Answer {
                    result: 16,
                    errno: libc::EBUSY,
                    prefix: FULL.to_vec(),
                },
                Ok(FULL),
            ),
            "zero" => (
                Answer {
                    result: 16,
                    errno: libc::EBUSY,
                    prefix: vec![0; 16],
                },
                Err(EntropyError::Zero),
            ),
            error => {
                let code = match error {
                    "eacces" | "error" => libc::EACCES,
                    "eio" => libc::EIO,
                    "enosys" => libc::ENOSYS,
                    _ => panic!("unknown {name}"),
                };
                (
                    Answer {
                        result: -1,
                        errno: code,
                        prefix: vec![],
                    },
                    Err(EntropyError::Unavailable { code }),
                )
            }
        };
        (k, terminal, expected)
    };
    let mut answers = Vec::new();
    for k in 0..interruptions {
        answers.push(Answer {
            result: -1,
            errno: libc::EINTR,
            prefix: vec![0xa0 + k as u8; 7],
        });
    }
    answers.push(terminal.clone());
    let original = answers.clone();
    answers.push(Answer {
        result: 16,
        errno: 0,
        prefix: vec![0xff; 16],
    });
    SCRIPT.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Script {
            pending: answers.into(),
            reached: vec![],
        });
    });
    let _installed = Installed;
    let observed = boot_nonce();
    SCRIPT.with(|slot| {
        let slot = slot.borrow();
        let script = slot.as_ref().unwrap();
        assert_eq!(
            script.reached.len(),
            interruptions + 1,
            "finite k+1 call count: {name}"
        );
        assert_eq!(
            script.pending.len(),
            1,
            "terminal draw leaves later entry: {name}"
        );
        if let Ok(nonce) = observed {
            assert_eq!(
                script.reached.last().unwrap().result,
                16,
                "successful nonce byte/count oracle"
            );
            assert_eq!(nonce, FULL, "successful nonce exact-byte oracle");
        }
        let mut before = [0; 16];
        for (call, answer) in script.reached.iter().zip(&original) {
            assert_eq!((call.length, call.flags), (16, 0), "request oracle");
            assert_eq!(
                call.before, before,
                "interrupted prefix persisted until replacement"
            );
            before[..answer.prefix.len()].copy_from_slice(&answer.prefix);
        }
    });
    assert_eq!(observed, expected, "entropy verdict: {name}");
    assert!(
        begun.elapsed() < DEADLINE,
        "{name}: missing deadline evidence"
    );
}
fn exhausted() {
    SCRIPT.with(|slot| {
        *slot.borrow_mut() = Some(Script {
            pending: VecDeque::from([Answer {
                result: -1,
                errno: libc::EINTR,
                prefix: vec![9; 5],
            }]),
            reached: vec![],
        })
    });
    let _installed = Installed;
    let panic = std::panic::catch_unwind(boot_nonce).unwrap_err();
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(text.contains("entropy script exhausted"), "{text}");
}
#[test]
fn complete_entropy_returns_exact_bytes() {
    run("full");
}
#[test]
fn complete_zero_entropy_is_zero() {
    run("zero");
}
#[test]
fn terminal_entropy_errors_consume_one_call() {
    for name in ["eacces", "eio", "enosys"] {
        run(name);
    }
}
#[test]
fn finite_interruptions_replace_modified_prefix_and_finish() {
    for name in [
        "eintr-1-full",
        "eintr-1-zero",
        "eintr-1-error",
        "eintr-3-full",
        "eintr-3-zero",
        "eintr-3-error",
        "eintr-8-full",
        "eintr-8-zero",
        "eintr-8-error",
        "eintr-short",
    ] {
        run(name);
    }
}
#[test]
fn entropy_script_exhaustion_fails_explicitly() {
    exhausted();
}
#[test]
fn every_frozen_entropy_case_has_a_byte_and_count_witness() {
    let mut witnessed = Vec::new();
    for n in 0..16 {
        let name = format!("short-{n}");
        run(&name);
        witnessed.push(name);
    }
    for name in [
        "full",
        "zero",
        "eacces",
        "eio",
        "enosys",
        "eintr-1-full",
        "eintr-1-zero",
        "eintr-1-error",
        "eintr-3-full",
        "eintr-3-zero",
        "eintr-3-error",
        "eintr-8-full",
        "eintr-8-zero",
        "eintr-8-error",
        "eintr-short",
    ] {
        run(name);
        witnessed.push(name.to_owned());
    }
    exhausted();
    witnessed.push("exhaustion".to_owned());
    assert_eq!(witnessed.len(), REQUIRED.len());
    for name in REQUIRED {
        assert_eq!(
            witnessed.iter().filter(|s| s.as_str() == name).count(),
            1,
            "missing or repeated {name}"
        );
    }
}
#[test]
fn short_0_entropy_is_unavailable() {
    run("short-0");
}
#[test]
fn short_1_entropy_is_unavailable() {
    run("short-1");
}
#[test]
fn short_2_entropy_is_unavailable() {
    run("short-2");
}
#[test]
fn short_3_entropy_is_unavailable() {
    run("short-3");
}
#[test]
fn short_4_entropy_is_unavailable() {
    run("short-4");
}
#[test]
fn short_5_entropy_is_unavailable() {
    run("short-5");
}
#[test]
fn short_6_entropy_is_unavailable() {
    run("short-6");
}
#[test]
fn short_7_entropy_is_unavailable() {
    run("short-7");
}
#[test]
fn short_8_entropy_is_unavailable() {
    run("short-8");
}
#[test]
fn short_9_entropy_is_unavailable() {
    run("short-9");
}
#[test]
fn short_10_entropy_is_unavailable() {
    run("short-10");
}
#[test]
fn short_11_entropy_is_unavailable() {
    run("short-11");
}
#[test]
fn short_12_entropy_is_unavailable() {
    run("short-12");
}
#[test]
fn short_13_entropy_is_unavailable() {
    run("short-13");
}
#[test]
fn short_14_entropy_is_unavailable() {
    run("short-14");
}
#[test]
fn short_15_entropy_is_unavailable() {
    run("short-15");
}
