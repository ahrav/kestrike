//! Receipt writer stages preserve the first offered failure in Ended.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use super::*;
use crate::storage::owner_fixture::{Device, TestPlatform, arena_on, heap_storage_on};

const DEADLINE: Duration = Duration::from_secs(10);
const REQUIRED_PRIORS: [&str; 17] = [
    "none",
    "bytes",
    "cancelled",
    "stalled",
    "missing",
    "read",
    "refused",
    "begin",
    "fill",
    "lookup",
    "invalidate",
    "credits",
    "untracked",
    "inconclusive",
    "maintenance",
    "interrupted",
    "receipt",
];
const REQUIRED_STAGES: [&str; 4] = ["checkpoint", "final", "flush", "success"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Checkpoint,
    Final,
    Flush,
}
#[derive(Debug)]
struct Attempt {
    stage: Stage,
    requested: Vec<u8>,
    result: Result<usize, io::ErrorKind>,
}
struct Writer {
    fault: Option<Stage>,
    stage: Stage,
    attempts: Vec<Attempt>,
    bytes: Vec<u8>,
    prefix: [bool; 2],
    interrupted: [bool; 2],
    failed: bool,
}
impl Writer {
    fn new(fault: Option<Stage>) -> Self {
        Self {
            fault,
            stage: Stage::Checkpoint,
            attempts: vec![],
            bytes: vec![],
            prefix: [false; 2],
            interrupted: [false; 2],
            failed: false,
        }
    }
}
impl Write for Writer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        assert!(self.attempts.len() < 10000, "writer script exhausted");
        if buffer.starts_with(b"{\"envelope\"") {
            self.stage = if buffer.windows(11).any(|bytes| bytes == b"\"lifecycle\"") {
                Stage::Final
            } else {
                Stage::Checkpoint
            };
        }
        let at = usize::from(self.stage == Stage::Final);
        let result = if !self.prefix[at] {
            self.prefix[at] = true;
            Ok(buffer.len().min(17))
        } else if !self.interrupted[at] {
            self.interrupted[at] = true;
            Err(io::ErrorKind::Interrupted)
        } else if self.fault == Some(self.stage) && !self.failed {
            self.failed = true;
            Err(io::ErrorKind::BrokenPipe)
        } else {
            Ok(buffer.len())
        };
        self.attempts.push(Attempt {
            stage: self.stage,
            requested: buffer.to_vec(),
            result,
        });
        match result {
            Ok(count) => {
                self.bytes.extend_from_slice(&buffer[..count]);
                Ok(count)
            }
            Err(kind) => Err(io::Error::from(kind)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let result = if self.fault == Some(Stage::Flush) {
            self.failed = true;
            Err(io::ErrorKind::BrokenPipe)
        } else {
            Ok(0)
        };
        self.attempts.push(Attempt {
            stage: Stage::Flush,
            requested: vec![],
            result,
        });
        result.map(|_| ()).map_err(io::Error::from)
    }
}
fn prior(name: &str) -> Option<SoakFailure> {
    let op = ReadOp {
        slot: 7,
        generation: 19,
    };
    Some(match name {
        "none" => return None,
        "bytes" => SoakFailure::Bytes {
            key: 2,
            generation: 9,
        },
        "cancelled" => SoakFailure::Cancelled {
            run: 31,
            id: 37,
            op,
        },
        "stalled" => SoakFailure::Stalled {
            run: 31,
            id: 37,
            op,
            deadline: 41,
        },
        "missing" => SoakFailure::Missing {
            key: 2,
            generation: 9,
        },
        "read" => SoakFailure::Read {
            key: 2,
            status: ReadStatus::DeviceError,
        },
        "refused" => SoakFailure::Refused {
            key: 2,
            refusal: ReadRefusal::Lost,
        },
        "begin" => SoakFailure::Begin {
            key: 2,
            error: BeginError::Corrupt,
        },
        "fill" => SoakFailure::Fill { key: 2 },
        "lookup" => SoakFailure::Lookup {
            key: 2,
            error: LookupError::ClockUnavailable,
        },
        "invalidate" => SoakFailure::Invalidate {
            key: 2,
            error: InvalidateError::Corrupt,
        },
        "credits" => SoakFailure::Credits {
            leases: 2,
            reported: Some(3),
        },
        "untracked" => SoakFailure::Untracked,
        "inconclusive" => SoakFailure::Inconclusive,
        "maintenance" => SoakFailure::Maintenance {
            contended: 1,
            clock_unavailable: true,
        },
        "interrupted" => SoakFailure::Interrupted,
        "receipt" => SoakFailure::Receipt,
        _ => panic!("unknown prior {name}"),
    })
}
fn exercise(stage: &str, first: &str) {
    let begun = Instant::now();
    let fault = match stage {
        "checkpoint" => Some(Stage::Checkpoint),
        "final" => Some(Stage::Final),
        "flush" => Some(Stage::Flush),
        "success" => None,
        _ => panic!("unknown {stage}"),
    };
    let storage = heap_storage_on(512 << 10, 64 << 10);
    let arena = arena_on(TestPlatform::heap(4096), 16, 8);
    let Device { volume, control } = Device::new(&storage, &arena);
    let config = SoakConfig {
        seed: 0x5eed,
        keys: NonZeroU8::new(4).unwrap(),
        body_cap: 100,
        capacity: 8,
        pressure: 2,
        cut_every: 8,
        patience: Duration::from_secs(1),
    };
    let mut soak = Soak::new(
        &storage,
        volume,
        storage.register().unwrap(),
        config,
        Writer::new(fault),
    );
    soak.device = Some(control);
    soak.step().unwrap();
    assert_eq!(
        soak.stepped, 1,
        "close checkpoint has a nonzero stepped window"
    );
    assert_eq!(soak.failure(), None, "workload setup completed");
    let first = prior(first);
    if let Some(first) = first {
        soak.fail(first);
        assert_eq!(soak.failure(), Some(first));
    }
    let ended = soak.close();
    let expected = first.or(fault.map(|_| SoakFailure::Receipt));
    assert_eq!(
        ended.failure, expected,
        "Ended first-failure precedence oracle"
    );
    assert!(
        matches!(ended.closed, Closed::Drained(_)),
        "writer result preserves drained custody"
    );
    let writer = ended.receipt;
    assert_eq!(
        writer.failed,
        fault.is_some(),
        "intended writer stage reached"
    );
    let stages: Vec<_> = writer.attempts.iter().map(|call| call.stage).collect();
    assert_eq!(stages.first(), Some(&Stage::Checkpoint));
    assert!(stages.contains(&Stage::Final));
    assert_eq!(
        stages
            .iter()
            .filter(|&&stage| stage == Stage::Flush)
            .count(),
        usize::from(fault != Some(Stage::Final)),
        "flush census: failed final skips; successful final flushes once"
    );
    for stage in [Stage::Checkpoint, Stage::Final] {
        let calls: Vec<_> = writer
            .attempts
            .iter()
            .filter(|call| call.stage == stage)
            .collect();
        assert!(calls.len() >= 3);
        assert_eq!(calls[0].result, Ok(17), "partial write reached");
        assert_eq!(
            calls[1].result,
            Err(io::ErrorKind::Interrupted),
            "interrupted write reached"
        );
        assert_eq!(
            calls[1].requested,
            calls[0].requested[17..],
            "partial advances exact prefix"
        );
        assert_eq!(
            calls[2].requested, calls[1].requested,
            "Interrupted retries identical bytes"
        );
        let errors: Vec<_> = calls
            .iter()
            .filter(|call| call.result == Err(io::ErrorKind::BrokenPipe))
            .collect();
        assert_eq!(
            errors.len(),
            usize::from(fault == Some(stage)),
            "stage-tagged error census"
        );
    }
    let text = String::from_utf8(writer.bytes).unwrap();
    if matches!(fault, None | Some(Stage::Flush)) {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert_eq!(
            lines.len(),
            2,
            "write-fault-free close emits one checkpoint line then one final line: {text}"
        );
        for (line, lifecycle) in lines.iter().zip([false, true]) {
            assert!(
                line.starts_with("{\"envelope\"") && line.ends_with("}\n"),
                "complete receipt line: {line}"
            );
            assert_eq!(
                line.contains("\"lifecycle\""),
                lifecycle,
                "checkpoint precedes final: {line}"
            );
        }
    }
    if fault != Some(Stage::Final) {
        let final_line = text
            .lines()
            .find(|line| line.contains("\"lifecycle\""))
            .unwrap();
        let encoded = if fault == Some(Stage::Checkpoint) {
            first.or(Some(SoakFailure::Receipt))
        } else {
            first
        };
        assert!(
            final_line.contains(&format!("\"failure\": \"{encoded:?}\"")),
            "final JSON is a pre-flush observation: {final_line}"
        );
    }
    assert!(begun.elapsed() < DEADLINE, "writer case missed deadline");
}
#[test]
fn checkpoint_writer_failure_selects_receipt() {
    exercise("checkpoint", "none");
}
#[test]
fn final_writer_failure_selects_receipt_and_skips_flush() {
    exercise("final", "none");
}
#[test]
fn flush_writer_failure_selects_receipt_in_returned_ended() {
    exercise("flush", "none");
}
#[test]
fn successful_partial_interrupted_writes_flush_once() {
    exercise("success", "none");
}
#[test]
fn checkpoint_writer_failure_preserves_every_prior_category() {
    for first in &REQUIRED_PRIORS[1..] {
        exercise("checkpoint", first);
    }
}
#[test]
fn final_writer_failure_preserves_every_prior_category() {
    for first in &REQUIRED_PRIORS[1..] {
        exercise("final", first);
    }
}
#[test]
fn flush_writer_failure_preserves_every_prior_category() {
    for first in &REQUIRED_PRIORS[1..] {
        exercise("flush", first);
    }
}
#[test]
fn successful_writer_preserves_every_prior_category() {
    for first in &REQUIRED_PRIORS[1..] {
        exercise("success", first);
    }
}
#[test]
fn every_frozen_writer_stage_and_prior_has_an_attempt_witness() {
    let mut witnessed = Vec::new();
    for stage in ["checkpoint", "final", "flush", "success"] {
        for first in [
            "none",
            "bytes",
            "cancelled",
            "stalled",
            "missing",
            "read",
            "refused",
            "begin",
            "fill",
            "lookup",
            "invalidate",
            "credits",
            "untracked",
            "inconclusive",
            "maintenance",
            "interrupted",
            "receipt",
        ] {
            exercise(stage, first);
            assert!(!witnessed.contains(&(stage, first)));
            witnessed.push((stage, first));
        }
    }
    assert_eq!(
        witnessed.len(),
        REQUIRED_STAGES.len() * REQUIRED_PRIORS.len()
    );
    for stage in REQUIRED_STAGES {
        for first in REQUIRED_PRIORS {
            assert!(witnessed.contains(&(stage, first)));
        }
    }
}
