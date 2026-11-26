//! A returned address ends one episode; reuse carries another incarnation.

mod real;

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Identity(u16, u32, u64);

#[derive(Debug, Clone)]
struct Segment {
    episode: u32,
    chain: usize,
    address: usize,
    pool: usize,
    index: u32,
    token: Identity,
    baseline: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    returns: usize,
    token: Option<Identity>,
    out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Census {
    class: usize,
    incarnation: u64,
    nic: u16,
    free: bool,
}

#[derive(Debug, Clone, Default)]
struct Boundary {
    segments: BTreeMap<usize, Observation>,
    buffers: BTreeMap<(u16, u32), Census>,
    descriptors: Vec<u32>,
}

#[derive(Debug, Clone)]
struct Ledger {
    segments: Vec<Segment>,
    sources: Vec<Identity>,
    headers: u32,
    descriptors: u32,
    source_count: u32,
}

impl Ledger {
    fn judge(
        &self,
        held: &BTreeSet<usize>,
        application: bool,
        seen: &Boundary,
    ) -> Result<(), String> {
        let mut addresses = BTreeSet::new();
        let mut live_descriptors = BTreeSet::new();
        let mut headers = BTreeMap::new();
        let mut references = BTreeMap::<Identity, u16>::new();
        for segment in &self.segments {
            if segment.episode == 0 || !addresses.insert(segment.address) {
                return Err("duplicate segment or missing episode".into());
            }
            let live = held.contains(&segment.chain);
            let expected = Observation {
                returns: segment.baseline + usize::from(!live),
                token: live.then_some(segment.token),
                out: live && segment.pool == 1,
            };
            if seen.segments.get(&segment.address) != Some(&expected) {
                return Err(format!(
                    "segment {}: {:?} != {expected:?}",
                    segment.address,
                    seen.segments.get(&segment.address)
                ));
            }
            match segment.pool {
                0 => {
                    if segment.token.0 != 4
                        || segment.token.1 != segment.index
                        || headers
                            .insert(segment.index, (segment.token.2, live))
                            .is_some()
                    {
                        return Err("header identity".into());
                    }
                }
                1 => {
                    if !self.sources.contains(&segment.token) {
                        return Err("source identity".into());
                    }
                    if live {
                        if !live_descriptors.insert(segment.index) {
                            return Err("descriptor alias".into());
                        }
                        *references.entry(segment.token).or_default() += 1;
                    }
                }
                _ => return Err("segment pool".into()),
            }
        }
        if seen.segments.len() != addresses.len() {
            return Err("unexpected segment".into());
        }
        let expected: BTreeSet<_> = (0..self.descriptors)
            .filter(|index| !live_descriptors.contains(index))
            .collect();
        if seen.descriptors.len() != expected.len()
            || seen.descriptors.iter().copied().collect::<BTreeSet<_>>() != expected
        {
            return Err("descriptor free census".into());
        }
        for index in 0..self.headers {
            let expected = headers.get(&index).map(|&(incarnation, live)| Census {
                class: if live { 5 } else { 0 },
                incarnation: incarnation + u64::from(!live),
                nic: u16::from(live),
                free: !live,
            });
            let actual = seen
                .buffers
                .get(&(4, index))
                .ok_or("missing header census")?;
            if let Some(expected) = expected {
                if *actual != expected {
                    return Err("header census".into());
                }
            } else if actual.class != 0 || actual.nic != 0 || !actual.free {
                return Err("unused header census".into());
            }
        }
        for index in 0..self.source_count {
            let source = self.sources.iter().find(|id| id.1 == index);
            let nic = source.map_or(0, |id| references.get(id).copied().unwrap_or(0));
            let app = source.is_some() && application;
            let live = app || nic > 0;
            let actual = seen
                .buffers
                .get(&(0, index))
                .ok_or("missing source census")?;
            if actual.class
                != if app {
                    1
                } else if live {
                    5
                } else {
                    0
                }
                || actual.nic != nic
                || actual.free == live
            {
                return Err("source NIC/free census".into());
            }
            if let Some(source) = source
                && actual.incarnation != source.2 + u64::from(!live)
            {
                return Err("source incarnation".into());
            }
        }
        if seen.buffers.len() != (self.headers + self.source_count) as usize {
            return Err("unexpected buffer census".into());
        }
        Ok(())
    }
}

fn sample() -> (Ledger, Boundary) {
    let source = Identity(0, 0, 7);
    let ledger = Ledger {
        segments: vec![
            Segment {
                episode: 1,
                chain: 0,
                address: 100,
                pool: 0,
                index: 0,
                token: Identity(4, 0, 9),
                baseline: 0,
            },
            Segment {
                episode: 1,
                chain: 0,
                address: 200,
                pool: 1,
                index: 0,
                token: source,
                baseline: 0,
            },
            Segment {
                episode: 1,
                chain: 0,
                address: 300,
                pool: 1,
                index: 1,
                token: source,
                baseline: 0,
            },
        ],
        sources: vec![source],
        headers: 1,
        descriptors: 3,
        source_count: 1,
    };
    let seen = Boundary {
        segments: ledger
            .segments
            .iter()
            .map(|segment| {
                (
                    segment.address,
                    Observation {
                        returns: 0,
                        token: Some(segment.token),
                        out: segment.pool == 1,
                    },
                )
            })
            .collect(),
        buffers: [
            (
                (4, 0),
                Census {
                    class: 5,
                    incarnation: 9,
                    nic: 1,
                    free: false,
                },
            ),
            (
                (0, 0),
                Census {
                    class: 5,
                    incarnation: 7,
                    nic: 2,
                    free: false,
                },
            ),
        ]
        .into(),
        descriptors: vec![2],
    };
    (ledger, seen)
}

#[test]
fn the_ledger_rejects_duplicate_returns_missing_suffix_and_wrong_source_counts() {
    let (ledger, seen) = sample();
    assert_eq!(ledger.judge(&[0].into(), false, &seen), Ok(()));
    let mut wrong = seen.clone();
    wrong.segments.get_mut(&200).unwrap().returns = 2;
    assert!(ledger.judge(&[0].into(), false, &wrong).is_err());
    assert!(ledger.judge(&BTreeSet::new(), false, &seen).is_err());
    let mut wrong = seen.clone();
    wrong.buffers.get_mut(&(0, 0)).unwrap().nic = 1;
    assert!(ledger.judge(&[0].into(), false, &wrong).is_err());
    let mut wrong = seen.clone();
    wrong.descriptors.push(2);
    assert!(ledger.judge(&[0].into(), false, &wrong).is_err());
    let mut wrong = seen;
    wrong.buffers.get_mut(&(0, 0)).unwrap().free = true;
    assert!(ledger.judge(&[0].into(), false, &wrong).is_err());
}

#[test]
fn the_ledger_requires_last_holder_return_and_distinct_reuse_episodes() {
    let (mut ledger, mut seen) = sample();
    assert_eq!(ledger.judge(&[0].into(), false, &seen), Ok(()));
    for observation in seen.segments.values_mut() {
        observation.returns = 1;
        observation.token = None;
        observation.out = false;
    }
    seen.descriptors = vec![0, 1, 2];
    *seen.buffers.get_mut(&(4, 0)).unwrap() = Census {
        class: 0,
        incarnation: 10,
        nic: 0,
        free: true,
    };
    *seen.buffers.get_mut(&(0, 0)).unwrap() = Census {
        class: 1,
        incarnation: 7,
        nic: 0,
        free: false,
    };
    assert_eq!(ledger.judge(&BTreeSet::new(), true, &seen), Ok(()));
    assert!(ledger.judge(&BTreeSet::new(), false, &seen).is_err());
    *seen.buffers.get_mut(&(0, 0)).unwrap() = Census {
        class: 0,
        incarnation: 8,
        nic: 0,
        free: true,
    };
    assert_eq!(ledger.judge(&BTreeSet::new(), false, &seen), Ok(()));
    ledger.segments[0].episode = 0;
    assert!(ledger.judge(&BTreeSet::new(), false, &seen).is_err());
}

fn sanitizer_control(id: &str, outcome: &crate::exact_child::Outcome, stderr: &[String]) -> bool {
    use crate::exact_child::Outcome;
    let stdout = match outcome {
        Outcome::Failed { status, stdout, .. } if !status.success() => stdout,
        Outcome::Crashed { stdout, .. } => stdout,
        _ => return false,
    };
    let entered = crate::exact_child::entered(id);
    stdout.iter().filter(|line| line.contains(&entered)).count() == 1
        && stdout.iter().filter(|line| line.contains("invalid-contract ready: returned descriptor backing released; second native free")).count() == 1
        && stderr.iter().any(|line| line.contains("ERROR: AddressSanitizer: heap-use-after-free"))
        && stderr.iter().any(|line| line.contains("spdk_sys_rte_pktmbuf_free"))
        && stdout
            .iter()
            .chain(stderr)
            .all(|line| !line.contains("escaped sanitizer"))
}

#[test]
fn the_invalid_contract_judge_requires_a_fatal_asan_report_and_the_free_shim_frame() {
    use crate::exact_child::Outcome;
    use std::os::unix::process::ExitStatusExt;
    let id = "native::chain_tests::real::invalid_contract_double_free";
    let stdout = vec![format!("exact child: {}", crate::exact_child::entered(id)), "exact child: invalid-contract ready: returned descriptor backing released; second native free".into()];
    let stderr = vec![
        "ERROR: AddressSanitizer: heap-use-after-free".into(),
        "#0 spdk_sys_rte_pktmbuf_free".into(),
    ];
    let failed = Outcome::Failed {
        status: std::process::ExitStatus::from_raw(256),
        stdout: stdout.clone(),
        stderr: stderr.clone(),
    };
    assert!(sanitizer_control(id, &failed, &stderr));
    assert!(!sanitizer_control(id, &failed, &stderr[..1]));
    assert!(!sanitizer_control(id, &failed, &stderr[1..]));
    // A recoverable report lets the second free return; the child's escape panic then prints to stderr and exits 101.
    let escaped = [
        stderr.as_slice(),
        &[
            format!(
                "thread '{id}' panicked at crates/kestrike/src/native/chain_tests/real.rs:585:9:"
            ),
            "invalid-contract free escaped sanitizer".into(),
        ],
    ]
    .concat();
    assert!(!sanitizer_control(
        id,
        &Outcome::Failed {
            status: std::process::ExitStatus::from_raw(101 << 8),
            stdout: stdout.clone(),
            stderr: escaped.clone()
        },
        &escaped
    ));
    assert!(!sanitizer_control(
        id,
        &Outcome::Completed {
            reports: stdout.clone()
        },
        &stderr
    ));
    assert!(!sanitizer_control(
        id,
        &Outcome::Stalled {
            reports: stdout.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone()
        },
        &stderr
    ));
    assert!(!sanitizer_control(
        id,
        &Outcome::Failed {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: stderr.clone()
        },
        &stderr
    ));
    let mut repeated = stdout;
    repeated.push(repeated[0].clone());
    assert!(!sanitizer_control(
        id,
        &Outcome::Crashed {
            signal: 6,
            stdout: repeated,
            stderr: stderr.clone()
        },
        &stderr
    ));
}
