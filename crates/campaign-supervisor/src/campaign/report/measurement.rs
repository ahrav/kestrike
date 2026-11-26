//! Resource totals select one attempt per published job and retain high-water provenance.

use super::{Error, coverage::total};
use crate::record::{Digest, ResourceBounds};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) struct MeasuredAttempt {
    pub job: Digest,
    pub attempt: u64,
    pub resources: ResourceBounds,
    pub virtual_us: Option<u64>,
    pub skipped_us: Option<u64>,
}

pub(super) fn totals(
    samples: &[Option<MeasuredAttempt>],
) -> Result<BTreeMap<&'static str, Value>, Error> {
    Ok([
        (
            "cpu_us",
            sum("cpu_us", samples, |sample| sample.resources.cpu_us)?,
        ),
        (
            "wall_us",
            sum("wall_us", samples, |sample| sample.resources.wall_us)?,
        ),
        (
            "virtual_us",
            sum("virtual_us", samples, |sample| sample.virtual_us)?,
        ),
        (
            "skipped_us",
            sum("skipped_us", samples, |sample| sample.skipped_us)?,
        ),
        (
            "memory_bytes",
            peak(samples, |sample| sample.resources.memory_bytes),
        ),
        ("pids", peak(samples, |sample| sample.resources.pids)),
    ]
    .into())
}

fn sum(
    name: &str,
    samples: &[Option<MeasuredAttempt>],
    field: impl Fn(&MeasuredAttempt) -> Option<u64>,
) -> Result<Value, Error> {
    total(
        name,
        &samples
            .iter()
            .map(|sample| sample.as_ref().and_then(&field))
            .collect::<Vec<_>>(),
    )
}

fn peak(
    samples: &[Option<MeasuredAttempt>],
    field: impl Fn(&MeasuredAttempt) -> Option<u64>,
) -> Value {
    let measured: Option<Vec<_>> = samples
        .iter()
        .map(|sample| {
            let sample = sample.as_ref()?;
            Some((sample, field(sample)?))
        })
        .collect();
    let best = measured.as_ref().and_then(|measured| {
        measured.iter().fold(
            None::<(&MeasuredAttempt, u64)>,
            |best, &(sample, value)| match best {
                Some((_, previous)) if previous >= value => best,
                _ => Some((sample, value)),
            },
        )
    });
    json!({"aggregation": "maximum", "value": best.map(|(_, value)| value),
        "measurement": if best.is_some() { "measured" } else { "unmeasured" },
        "reason": if samples.is_empty() { Some("no published attempts") } else if best.is_none() { Some("an operand is absent") } else { None },
        "source": best.map(|(sample, _)| json!({"job": sample.job, "attempt": sample.attempt}))})
}
