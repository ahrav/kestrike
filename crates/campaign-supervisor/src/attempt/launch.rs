//! Launch inputs configure execution and resource limits for a numbered attempt.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::custody::Limits;

/// Multiplies CPU, memory and output bounds by the frozen fork shares.
/// The pids bound adds one process per child; the per-file size limit stays fixed.
pub(crate) fn scaled(mut limits: Limits, shares: u64) -> Result<Limits, super::Error> {
    if shares == 0 {
        return Err(super::Error::Rejected("target shares must be positive"));
    }
    let multiply = |n: u64| {
        n.checked_mul(shares)
            .ok_or(super::Error::Rejected("target resource bounds overflow"))
    };
    limits.cpu_quota_us = multiply(limits.cpu_quota_us)?;
    limits.memory_bytes = multiply(limits.memory_bytes)?;
    limits.pids = limits
        .pids
        .checked_add(shares - 1)
        .ok_or(super::Error::Rejected("target member bound overflows"))?;
    limits.cpu_seconds = multiply(limits.cpu_seconds)?;
    limits.output_bytes = multiply(limits.output_bytes)?;
    limits.output_inodes = multiply(limits.output_inodes)?;
    limits.validate()?;
    Ok(limits)
}

/// Caller-supplied execution settings for a numbered attempt.
/// The attempt derives its arguments and share-scaled limits from admission.
/// The launcher runs under custody and publishes evidence in the attempt artifact directory.
pub struct Launch {
    pub gate: PathBuf,
    pub launcher: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub limits: Limits,
}
