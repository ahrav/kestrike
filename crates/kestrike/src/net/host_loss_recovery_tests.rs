//! A shard whose owner, or whose owner and standby, are lost keeps its volume, and the shard record still names
//! the checkpoint the capturing tenure cut. The tenure that recovers the shard must attach that volume warm from
//! the named cut and serve the cut's entries.
//!
//! Every run below is `cycles::run`: each cycle recovers the shard through the production `Restart::run` or
//! `Takeover::run` over the store double, attaches the retained media through `ServingAuthority::restarted`, and
//! reads every object the history knows in an opening sweep. The harness requires of each attach it expects warm
//! that the device accepted no write before the sweep (`a warm attach writes nothing`), so a run that returns a
//! report made every one of its attaches without a device write.
//!
//! `run` owns the fixtures, so assertions after the tenures end can inspect only the returned `Report`.

use super::takeover_history_tests::cycles::tape::Mix;
use super::takeover_history_tests::cycles::{Config, Report, Verdict, run};
use crate::sim::cut::Class;

const SEEDS: [u64; 3] = [27, 1, 5];

const CYCLES: u32 = 6;

/// The failures of `report` against the recovery rule, each as one line; empty when the run upholds it.
///
/// Each `report.cycles` entry represents a recovery that reached `Live`; `cycle.eligible` counts the entries the
/// harness expects its opening sweep to serve, and `cycle.served` counts the expected entries the sweep served.
/// With `mix.fill`, `mix.invalidate`, and `damage` all zero, the captured `entries` count is the expected count
/// for every opening sweep.
fn broken(report: &Report, entries: u32) -> Vec<String> {
    let mut lines = Vec::new();
    if report.cycles.len() != CYCLES as usize {
        lines.push(format!(
            "{} of {CYCLES} recoveries reached a serving tenure",
            report.cycles.len()
        ));
    }
    let verdicts = [
        &report.safety,
        &report.containment,
        &report.retention,
        &report.progress,
    ];
    if !verdicts.into_iter().all(Verdict::passed) {
        lines.push(format!("a verdict failed: {}", report.summary()));
    }
    if report.oracle != [None, None] {
        lines.push(format!("the oracle names {:?}", report.oracle));
    }
    let named = report
        .cycles
        .first()
        .map(|first| (first.cut.0, first.cut.1));
    for (at, cycle) in report.cycles.iter().enumerate() {
        if Some((cycle.cut.0, cycle.cut.1)) != named {
            lines.push(format!(
                "cycle {at} names checkpoint {:?}, not the capturing tenure's {named:?}",
                cycle.cut
            ));
        }
        if (cycle.eligible, cycle.served) != (entries, entries) {
            lines.push(format!(
                "cycle {at} ({:?}, {:?}) served {} of {} retained entries, the cut holds {entries}",
                cycle.recovery, cycle.class, cycle.served, cycle.eligible
            ));
        }
    }
    lines
}

/// A run with no FILL, no INVALIDATE and no damage retains exactly the cut. Every recovered tenure's opening
/// sweep serves all of the cut's captured objects, so no recovery lost an entry of the cut it attached.
#[test]
fn every_recovered_tenure_serves_exactly_the_cuts_entries() {
    for seed in SEEDS {
        let config = Config {
            damage: 0,
            mix: Mix {
                fill: 0,
                invalidate: 0,
            },
            ..Config::discovery(seed, CYCLES)
        };
        assert!(config.objects > 0, "premise: the cut captures an object");
        let report = run(&config);
        let lines = broken(&report, u32::from(config.objects));
        assert!(lines.is_empty(), "seed {seed}: {}", lines.join("; "));
        assert!(
            report
                .cycles
                .iter()
                .any(|cycle| cycle.class != Class::ProcessDeath),
            "premise: seed {seed} composes a host loss"
        );
    }
}
