//! ```text
//! KESTRIKE_MAPPINGS=<state dir>/mappings KESTRIKE_SOAK_RECEIPT=<path> \
//!     KESTRIKE_N_REG=<registrants> \
//!     KESTRIKE_N_RESV=2 KESTRIKE_T_REPORT=<positive owner-clock units> KESTRIKE_T_PA=<positive owner-clock units> \
//!     KESTRIKE_N_RETRY=<positive count> KESTRIKE_SERVING_WINDOW_US=<microseconds> \
//!     KESTRIKE_REPORT_PERIOD_US=<positive microseconds> KESTRIKE_CLOCK_ERROR_US=<microseconds> \
//!     [KESTRIKE_SOAK_SECONDS=<n>] [KESTRIKE_SOAK_SEED=<n>] [KESTRIKE_ALLOW_NO_IOMMU=1] \
//!     kestrike-soak
//! ```
//!
//! The command exits 0 when the soak drained with no failure, 1 when it
//! recorded a failure, a failed receipt write included, or ended
//! inconclusive, and 2 for a usage error, a receipt it cannot create, a
//! composition error, a stop, unregistration or detach error, or a drain,
//! environment finish or arena release error of a run that recorded no
//! failure. A stop that stays unproven keeps the process parked with its
//! mappings and outstanding commands held.
//!
//! The state directory must be a 0700 directory of the running user under
//! ancestors only root or that user can write, outside `/run` and
//! `/var/run`. Each run past the mappings check creates or bumps the shard
//! record in the state directory's `soak-store`, so it consumes one attempt
//! even when it fails later. That store stays with the bound volume for the
//! volume's whole life; a store refusal exits 2 before any device access.

use std::env::VarError;
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use kestrike::soak::{BoundConfig, SMOKE, SMOKE_BOUND, SoakConfig, open_receipt, soak_bound};

fn number(name: &str, default: u64) -> Option<u64> {
    match std::env::var(name) {
        Ok(text) => text.parse().ok(),
        Err(VarError::NotPresent) => Some(default),
        Err(VarError::NotUnicode(_)) => None,
    }
}

fn main() -> ExitCode {
    let (Some(mappings), Some(receipt_path), Some(seconds), Some(seed)) = (
        std::env::var_os("KESTRIKE_MAPPINGS"),
        std::env::var_os("KESTRIKE_SOAK_RECEIPT"),
        number("KESTRIKE_SOAK_SECONDS", 60).filter(|&seconds| seconds > 0),
        number("KESTRIKE_SOAK_SEED", 1),
    ) else {
        eprintln!(
            "kestrike-soak: set KESTRIKE_MAPPINGS and KESTRIKE_SOAK_RECEIPT, and give numbers, KESTRIKE_SOAK_SECONDS above zero"
        );
        return ExitCode::from(2);
    };
    if Path::new(&mappings).file_name() != Some(OsStr::new("mappings")) {
        eprintln!("kestrike-soak: KESTRIKE_MAPPINGS names the state directory's `mappings` file");
        return ExitCode::from(2);
    }
    let bound = BoundConfig {
        run: Duration::from_secs(seconds),
        allow_no_iommu: std::env::var("KESTRIKE_ALLOW_NO_IOMMU").is_ok_and(|value| value == "1"),
        ..SMOKE_BOUND
    };
    let file = |state: &Path| open_receipt(Path::new(&receipt_path), state);
    match soak_bound(mappings.as_ref(), SoakConfig { seed, ..SMOKE }, bound, file) {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(failure)) => {
            eprintln!("kestrike-soak: {failure:?}");
            if let Some(remedy) = failure.remedy() {
                eprintln!("kestrike-soak: {remedy}");
            }
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("kestrike-soak: {error}");
            ExitCode::from(2)
        }
    }
}
