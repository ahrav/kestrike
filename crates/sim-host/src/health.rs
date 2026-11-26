//! The runner's local health record, `health.json` in the state
//! directory: its phase, reasons, errors and CPU shares. [`save`] cuts the
//! reason and error texts to [`TEXT_MAX`] bytes and refuses an encoding
//! past the [`BOUND`] that `sim-host status` reads it with.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const BOUND: u64 = 1 << 20;
pub const TEXT_MAX: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Sweeping,
    Waiting,
    Held,
    Full,
    Blocked,
    Stopped,
}

impl Phase {
    pub const ALL: [Self; 7] = [
        Self::Starting,
        Self::Sweeping,
        Self::Waiting,
        Self::Held,
        Self::Full,
        Self::Blocked,
        Self::Stopped,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Sweeping => "sweeping",
            Self::Waiting => "waiting",
            Self::Held => "held",
            Self::Full => "full",
            Self::Blocked => "blocked",
            Self::Stopped => "stopped",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.name() == name)
    }

    pub fn critical(self) -> bool {
        match self {
            Self::Starting | Self::Sweeping => false,
            Self::Waiting | Self::Held | Self::Full | Self::Blocked | Self::Stopped => true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Health {
    pub format: Option<u32>,
    pub written: Option<u64>,
    pub instance: Option<String>,
    pub build: Option<String>,
    pub root: Option<String>,
    pub assignment: Option<String>,
    pub assignment_error: Option<String>,
    pub upload_error: Option<String>,
    pub fetch_error: Option<String>,
    pub cleanup_error: Option<String>,
    pub stint: Option<u64>,
    pub stint_seconds: Option<u64>,
    pub phase: Option<String>,
    pub reason: Option<String>,
    /// Whether the running sweep has passed the runner's deadline for it.
    pub sweep_overdue: Option<bool>,
    pub exits: Option<BTreeMap<String, i32>>,
    pub alarm: Option<bool>,
    pub confirmation: Option<String>,
    pub confirmation_reason: Option<String>,
    pub confirming: Option<String>,
    pub confirm_exit_root: Option<String>,
    pub held_roots: Option<u64>,
    pub held_root_names: Option<Vec<String>>,
    pub share_stint: Option<u64>,
    pub stint_cpu_usec: Option<u64>,
    pub stint_capacity_usec: Option<u64>,
    pub cpu_usec: Option<u64>,
    pub capacity_usec: Option<u64>,
}

pub const HOSTS: &str = "hosts/";
pub const NAME: &str = "health.json";

pub fn path(state: &Path) -> PathBuf {
    state.join(NAME)
}

pub fn key(instance: &str) -> String {
    format!("{HOSTS}{instance}/{NAME}")
}

/// The copy staged in `state/store` has a name fixed per instance, so the
/// caller runs one upload per state directory and instance at a time.
pub fn upload(bucket: &crate::store::Bucket, state: &Path, instance: &str) -> Result<(), String> {
    let local = path(state);
    let bytes = crate::file::read_plain(&local, BOUND)
        .map_err(|error| format!("{}: {error}", local.display()))?
        .ok_or_else(|| format!("{} is missing", local.display()))?;
    let key = key(instance);
    let scratch = state.join("store");
    crate::file::private_dir(&scratch)
        .map_err(|error| format!("{}: {error}", scratch.display()))?;
    let staged = scratch.join(key.replace('/', "_"));
    let written = crate::file::create_fresh(&staged).and_then(|mut file| file.write_all(&bytes));
    let stored = match written {
        Ok(()) => bucket
            .replace(&key, &staged, crate::store::SHORT)
            .map_err(|error| format!("{key}: {error}")),
        Err(error) => Err(format!("{}: {error}", staged.display())),
    };
    let _ = std::fs::remove_file(&staged);
    stored
}

pub fn parse(bytes: &[u8]) -> Result<Health, String> {
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err("is not a JSON object".to_owned());
    }
    serde_json::from_slice(bytes).map_err(|error| format!("does not parse: {error}"))
}

pub fn save(state: &Path, health: &Health) -> Result<(), String> {
    let cut = |text: &Option<String>| text.as_deref().map(|text| crate::file::cut(text, TEXT_MAX));
    let health = Health {
        assignment_error: cut(&health.assignment_error),
        upload_error: cut(&health.upload_error),
        fetch_error: cut(&health.fetch_error),
        cleanup_error: cut(&health.cleanup_error),
        reason: cut(&health.reason),
        confirmation_reason: cut(&health.confirmation_reason),
        ..health.clone()
    };
    crate::file::save_json(&path(state), &health, BOUND)
}

#[cfg(test)]
pub(crate) fn positional(health: &Health) -> Vec<u8> {
    let mut fields = vec![serde_json::Value::Null; 28];
    fields[0] = serde_json::json!(health.format);
    fields[1] = serde_json::json!(health.written);
    fields[11] = serde_json::json!(health.stint_seconds);
    fields[12] = serde_json::json!(health.phase);
    serde_json::to_vec(&fields).expect("an array")
}

#[cfg(test)]
mod tests {
    use super::positional;

    #[test]
    fn a_phase_name_parses_back_and_only_two_phases_are_healthy() {
        for phase in super::Phase::ALL {
            assert_eq!(super::Phase::parse(phase.name()), Some(phase));
        }
        let healthy: Vec<_> = super::Phase::ALL
            .into_iter()
            .filter(|phase| !phase.critical())
            .map(super::Phase::name)
            .collect();
        assert_eq!(healthy, ["starting", "sweeping"]);
        assert_eq!(super::Phase::parse("swept"), None);
    }

    #[test]
    fn long_reasons_are_cut_so_the_record_reads_back() {
        let dir = crate::file::scratch("health");
        let health = super::Health {
            reason: Some("r".repeat(super::BOUND as usize)),
            assignment_error: Some("e".repeat(super::BOUND as usize)),
            ..super::Health::default()
        };
        super::save(&dir, &health).expect("it saves");
        let bytes = crate::file::read(&super::path(&dir), super::BOUND)
            .expect("it reads")
            .expect("it exists");
        let saved: super::Health = serde_json::from_slice(&bytes).expect("it parses");
        assert_eq!(saved.reason.expect("a reason").len(), super::TEXT_MAX);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// A record is a JSON object: the positional array the derived parse
    /// also accepts is refused, as is an empty record.
    #[test]
    fn only_a_json_object_parses_as_a_record() {
        let health = super::Health {
            format: Some(1),
            phase: Some("sweeping".into()),
            ..super::Health::default()
        };
        let object = serde_json::to_vec(&health).expect("an object");
        assert_eq!(super::parse(&object), Ok(health.clone()));
        let positional = positional(&health);
        assert_eq!(
            serde_json::from_slice::<super::Health>(&positional).ok(),
            Some(health),
            "the derived parse takes the fields in order"
        );
        for bytes in [&positional[..], b"", b" \n", b"[1]"] {
            assert_eq!(
                super::parse(bytes),
                Err("is not a JSON object".to_owned()),
                "{bytes:?}"
            );
        }
    }

    /// An upload refuses a missing local record, a symlink at its path and
    /// one past the bound before it stages anything or calls the bucket.
    #[test]
    fn an_upload_refuses_a_missing_linked_or_oversized_record() {
        let dir = crate::file::scratch("upload-refused");
        let bucket = crate::store::Bucket::new("bucket");
        let path = super::path(&dir);
        let refused = |dir: &std::path::Path| {
            let error = super::upload(&bucket, dir, "i-0000000a").expect_err("refused");
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert!(!dir.join("store").exists(), "nothing is staged");
        };
        refused(&dir);
        let target = dir.join("other.json");
        std::fs::write(&target, b"{}").expect("a regular file");
        std::os::unix::fs::symlink(&target, &path).expect("a link");
        refused(&dir);
        std::fs::remove_file(&path).expect("the link is removed");
        std::fs::write(&path, vec![b' '; super::BOUND as usize + 1]).expect("a long record");
        refused(&dir);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
