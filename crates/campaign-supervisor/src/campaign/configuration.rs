//! Refused configuration changes preserve the recorded configuration.
//! `configure` uses the initial-configuration baseline when reading
//! `config.json` returns `Held::Mismatch`.

use std::collections::BTreeMap;

use super::{Error, name};
use crate::record::{Configuration, Text};
use crate::store::Store;

fn installable(config: &Configuration) -> Result<(), Error> {
    crate::sys::dispatch_limits(config.value("cpu"), config.file_bytes()).map_err(|error| {
        if error.raw_os_error().is_some() {
            Error::Held(error.to_string())
        } else {
            Error::Rejected(error.to_string())
        }
    })
}

pub(super) fn prepare(config: BTreeMap<Text, u64>) -> Result<Configuration, Error> {
    let config = Configuration::new(config).map_err(|e| Error::Rejected(e.to_string()))?;
    installable(&config)?;
    Ok(config)
}

/// Installs `config` as the state directory's configuration. Its capacity
/// is the arithmetic [`Configuration::new`] checks: `slots + reserve_slots`
/// attempts fit `cores`, and their `tree_memory` fits `memory`. Custody
/// enforces one CPU, `tree_memory` and `processes` on each attempt, so an
/// attempt that exceeds its share ends in its own limit class. A lower
/// `attempt_output` or
/// `attempt_inodes` applies to existing attempts and corpus probes. The
/// census uses the current configuration for their charges, so lowering
/// these limits undercounts entries written under the higher budget.
pub fn configure(store: &Store, config: Configuration) -> Result<Configuration, Error> {
    installable(&config)?;
    match store.read_record::<Configuration>(store.root(), &name("config.json")) {
        Ok(_) | Err(crate::record::Held::Mismatch) => {}
        Err(error) => return Err(error.into()),
    }
    store.replace_record(store.root(), &name("config.json"), &config)?;
    Ok(config)
}

pub(super) fn limits(config: &Configuration) -> crate::custody::Limits {
    crate::custody::Limits {
        cpu_quota_us: crate::store::cgroup::CPU_PERIOD_US,
        memory_bytes: config.value("tree_memory"),
        pids: config.value("processes"),
        file_bytes: config.file_bytes(),
        cpu_seconds: config.value("cpu"),
        output_bytes: config.file_bytes(),
        output_inodes: config.value("attempt_inodes"),
    }
}
