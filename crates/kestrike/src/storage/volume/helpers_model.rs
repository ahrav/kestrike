//! Loom kernel for the recovery helpers' adoption against cancellation: one helper thread runs a dispatched job while the owner either cancels the attempt or polls for the terminal, over every schedule of the job queue, the terminal channel and the thread's exit.
//!
//! Properties at the end of every execution: a terminal of a cancelled attempt is adopted by no poll, a terminal of the current attempt is adopted exactly once, and the pool holds no live job and no charge once every terminal reached the owner; dropping the pool joins the thread.

use super::helpers::{Charge, Helpers, RecoveryLimits};
use super::helpers_tests::job;

fn limits() -> RecoveryLimits {
    RecoveryLimits {
        cpus: super::CpuSet::current().expect("the thread's affinity mask"),
        helpers: 1,
        jobs: 2,
        input_bytes: 2 * 4096,
        output_bytes: 2 * 4096 * super::helpers::OUTPUT_PER_BYTE,
        adopt: 2,
        io: super::super::recovery::HostShare {
            bytes: 1 << 40,
            interval: 1,
            owners: 1,
        },
    }
}

/// Polls until no dispatched job runs and returns how many terminals the polls adopted.
fn adopted(helpers: &mut Helpers) -> usize {
    let mut adopted = 0;
    while helpers.busy() {
        let mut taken = 0;
        adopted += usize::from(helpers.poll(&mut taken).is_some());
        loom::thread::yield_now();
    }
    adopted
}

#[test]
fn a_cancelled_attempt_adopts_no_terminal_and_releases_its_charge() {
    loom::model(|| {
        let mut helpers = Helpers::start(limits(), 2).unwrap();
        let block = Charge::decode(4096);
        assert!(helpers.reserve(block));
        helpers.dispatch(block, job());
        helpers.cancel();
        assert_eq!(adopted(&mut helpers), 0, "a stale terminal was adopted");
        assert_eq!(helpers.held(), (0, Charge::default()));
    });
}

#[test]
fn the_current_attempt_adopts_its_terminal_once() {
    loom::model(|| {
        let mut helpers = Helpers::start(limits(), 2).unwrap();
        let block = Charge::decode(4096);
        assert!(helpers.reserve(block));
        helpers.dispatch(block, job());
        assert_eq!(adopted(&mut helpers), 1);
        assert_eq!(helpers.held(), (0, Charge::default()));
    });
}
