//! Loom kernel for a slot's binding, over the schedules loom explores with preemption bound 3: one writer rebinds the
//! route through the production [`Binding::publish`] while the model thread reads it through the production
//! [`Binding::read`].
//!
//! The binding starts Bound to `first`. The writer publishes a Bound route at a higher session whose host differs in
//! both words, so a read that pairs one binding's session with the other's host words is torn. Every read returns
//! `None` or one binding whole. The count of executions whose read returned a binding ensures that at least one
//! execution checks a returned binding.
//!
//! Negative controls: `Publish::WithoutFence` and `Read::WithoutRecheck` each let a read pair `first`'s session with
//! `second`'s host.
//!
//! A second kernel publishes a Candidate of `second` and then binds it, which stores the session word alone. Every
//! read returns `None`, `first` Bound, or `second` whole as a Candidate or Bound.
//!
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release route_model`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize as StdUsize, Ordering as StdOrdering};

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

use super::{Binding, CANDIDATE, words};
use crate::failover::identity::Exhid;
use crate::failover::route::{HighWater, key};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};

const PREEMPTION_BOUND: usize = 3;

#[derive(Clone, Copy)]
enum Publish {
    Production,
    WithoutFence,
}

#[derive(Clone, Copy)]
enum Read {
    Production,
    WithoutRecheck,
}

fn tenure(epoch: u32, host: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(1).unwrap(),
        epoch: ActivatedEpoch::new(2 * epoch).unwrap(),
        host: Exhid::new([host; 16]).unwrap(),
    }
}

fn recorded(tenure: Tenure) -> (u64, [u64; 2]) {
    (key(tenure.generation, tenure.epoch), words(tenure.host))
}

/// The control that tests the release fence: the production publish's stores in order, with no fence between the
/// session's clearing and the host stores.
fn publish_without_fence(binding: &Binding<AtomicU64>, tenure: Tenure) {
    binding.session.store(0, Ordering::Relaxed);
    let [low, high] = words(tenure.host);
    binding.host[0].store(low, Ordering::Relaxed);
    binding.host[1].store(high, Ordering::Relaxed);
    binding.session.store(recorded(tenure).0, Ordering::Release);
}

/// The control that tests the recheck: the production read's loads up to the host words, returned as read.
fn read_without_recheck(binding: &Binding<AtomicU64>) -> Option<(u64, [u64; 2])> {
    let session = binding.session.load(Ordering::Acquire);
    if session == 0 {
        return None;
    }
    let host = [
        binding.host[0].load(Ordering::Acquire),
        binding.host[1].load(Ordering::Acquire),
    ];
    Some((session, host))
}

fn kernel(publish: Publish, read: Read) {
    let reads = Arc::new(StdUsize::new(0));
    let counted = Arc::clone(&reads);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let (first, second) = (tenure(1, 1), tenure(2, 2));
        let binding = Arc::new(Binding {
            session: AtomicU64::new(0),
            host: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        binding.publish(HighWater::Bound(first));
        let writer = {
            let binding = Arc::clone(&binding);
            thread::spawn(move || match publish {
                Publish::Production => binding.publish(HighWater::Bound(second)),
                Publish::WithoutFence => publish_without_fence(&binding, second),
            })
        };
        let taken = match read {
            Read::Production => binding.read(),
            Read::WithoutRecheck => read_without_recheck(&binding),
        };
        if let Some(taken) = taken {
            assert!(
                taken == recorded(first) || taken == recorded(second),
                "torn binding {taken:x?}"
            );
            counted.fetch_add(1, StdOrdering::Relaxed);
        }
        writer.join().unwrap();
    });
    assert_ne!(
        reads.load(StdOrdering::Relaxed),
        0,
        "no schedule read a binding"
    );
}

#[test]
fn a_read_racing_a_rebind_takes_one_binding_whole() {
    let reads = Arc::new(StdUsize::new(0));
    let counted = Arc::clone(&reads);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let (first, second) = (tenure(1, 1), tenure(2, 2));
        let binding = Arc::new(Binding {
            session: AtomicU64::new(0),
            host: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        binding.publish(HighWater::Bound(first));
        let writer = {
            let binding = Arc::clone(&binding);
            thread::spawn(move || binding.publish(HighWater::Bound(second)))
        };
        if let Some(taken) = binding.read() {
            assert!(
                taken == recorded(first) || taken == recorded(second),
                "torn binding {taken:x?}"
            );
            counted.fetch_add(1, StdOrdering::Relaxed);
        }
        writer.join().unwrap();
    });
    assert_ne!(
        reads.load(StdOrdering::Relaxed),
        0,
        "no schedule read a binding"
    );
}

#[test]
fn a_read_racing_a_candidate_and_its_binding_takes_one_tenure_whole() {
    let reads = Arc::new(StdUsize::new(0));
    let counted = Arc::clone(&reads);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let (first, second) = (tenure(1, 1), tenure(2, 2));
        let binding = Arc::new(Binding {
            session: AtomicU64::new(0),
            host: [AtomicU64::new(0), AtomicU64::new(0)],
        });
        binding.publish(HighWater::Bound(first));
        let writer = {
            let binding = Arc::clone(&binding);
            thread::spawn(move || {
                binding.publish(HighWater::Candidate(second));
                binding.publish(HighWater::Bound(second));
            })
        };
        if let Some(taken) = binding.read() {
            let (session, host) = recorded(second);
            assert!(
                taken == recorded(first)
                    || taken == (session | CANDIDATE, host)
                    || taken == (session, host),
                "torn binding {taken:x?}"
            );
            counted.fetch_add(1, StdOrdering::Relaxed);
        }
        writer.join().unwrap();
    });
    assert_ne!(
        reads.load(StdOrdering::Relaxed),
        0,
        "no schedule read a binding"
    );
}

#[test]
#[should_panic(expected = "torn binding")]
fn negative_control_a_publish_without_its_fence_lets_a_read_tear() {
    kernel(Publish::WithoutFence, Read::Production);
}

#[test]
#[should_panic(expected = "torn binding")]
fn negative_control_a_read_without_its_recheck_tears() {
    kernel(Publish::Production, Read::WithoutRecheck);
}
