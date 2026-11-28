//! The hardware lane's exit codes, paths and waits, and the names, key sets and patterns its manifest check
//! reads.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::compiled;
use crate::text::Text;

/// The exit code of a lane run that leaves the custody of a stopped process group held.
pub const HELD: u8 = 4;

/// The exit code of a lane run that a signal interrupted.
pub const INTERRUPTED: u8 = 5;

/// The hardware manifest's path under the checkout's top level.
pub const MANIFEST: &str = "scripts/hardware-profiles.json";

/// The default window of one call of a case's containment controller, in seconds.
pub const CONTROLLER_SECONDS: f64 = 30.0;

/// The longest the lane waits for every member of a stopped process group to report stopped, in seconds.
pub const STOP_SECONDS: f64 = 10.0;

/// The bound of each observer operation a case may wait on, in seconds.
pub const OBSERVER_SECONDS: f64 = 5.0;

/// The directory where a held group's marker outlives the job, so the next run on the host refuses to start
/// beside it.
pub const CUSTODY_DIR: &str = "/var/tmp/kestrike-hardware-custody";

/// The two inputs a case names to get the two ends of its containment channel from the lane, the
/// requests first.
pub const CHANNEL: [&str; 2] = ["KESTRIKE_CONTROLLER_REQUESTS", "KESTRIKE_CONTROLLER_ACKS"];

/// The keys every profile holds.
pub const PROFILE_KEYS: [&str; 3] = ["platforms", "roles", "retries"];

/// A profile's disposition on each platform row, in the order a refusal lists them.
pub const DISPOSITIONS: [&str; 3] = ["runs", "pending", "excluded"];

/// The keys a profile may hold beside [`PROFILE_KEYS`].
pub const OPTIONAL_PROFILE_KEYS: [&str; 2] = ["conjunction", "evidence"];

/// The keys every case holds, and no other.
pub const CASE_KEYS: [&str; 8] = [
    "id",
    "expected",
    "inputs",
    "deadline",
    "grace",
    "witnesses",
    "restoration",
    "closes_on_sigterm",
];

/// The keys a role may hold.
pub const ROLE_KEYS: [&str; 6] = ["cases", "after", "ready", "closing", "env", "kill"];

/// The pattern a key of a role's `env` matches whole.
pub const ENVIRONMENT_NAME: &str = "KESTRIKE_[A-Z0-9_]+";

/// The pattern an episode name and a platform row's name match whole: one plain file name component.
pub const EPISODE_NAME: &str = "[A-Za-z0-9][A-Za-z0-9._-]*";

/// The pattern each PCI identity of an envelope's `devices` matches whole: the vendor and the device.
const DEVICE_IDENTITY: &str = "0x[0-9a-f]{4}:0x[0-9a-f]{4}";

/// The fields of a platform's envelope that a receipt's host facts must reproduce.
pub const OBSERVED: [&str; 10] = [
    "instance_type",
    "cpu_features",
    "cpu_family",
    "kernel",
    "firmware",
    "vfio",
    "numa_nodes",
    "page_size",
    "hugepage_size",
    "devices",
];

/// The fields a platform's envelope may hold, [`OBSERVED`] first, in the order a refusal lists those it
/// lacks.
pub const ENVELOPE_FIELDS: [&str; 20] = [
    "instance_type",
    "cpu_features",
    "cpu_family",
    "kernel",
    "firmware",
    "vfio",
    "numa_nodes",
    "page_size",
    "hugepage_size",
    "devices",
    "address_mode",
    "volume",
    "eni",
    "limits",
    "coherence",
    "disposable_resources",
    "reset_blast_radius",
    "fis_blast_radius",
    "restoration_authority",
    "containment_authority",
];

/// The values that stand for a host fact the lane cannot read.
pub const UNREAD: [&str; 1] = ["unreadable"];

/// The lines of `/proc/cpuinfo` that identify a CPU family on each machine: the raw MIDR implementer and
/// part on aarch64, and the vendor, family and model on x86_64.
pub const IDENTITY_LINES: [(&str, &[&str]); 2] = [
    ("aarch64", &["CPU implementer", "CPU part"]),
    ("x86_64", &["vendor_id", "cpu family", "model"]),
];

/// The identity lines of `machine`, or none for a machine [`IDENTITY_LINES`] does not name.
pub fn identity_lines(machine: &Text) -> &'static [&'static str] {
    IDENTITY_LINES
        .iter()
        .find(|(name, _)| machine == name)
        .map_or(&[], |(_, lines)| lines)
}

/// The hardware manifest under the checkout's top level `top`.
pub fn manifest_path(top: &Path) -> PathBuf {
    top.join(MANIFEST)
}

static EPISODE: LazyLock<Regex> = LazyLock::new(|| whole(EPISODE_NAME));
static ENVIRONMENT: LazyLock<Regex> = LazyLock::new(|| whole(ENVIRONMENT_NAME));
static DEVICE: LazyLock<Regex> = LazyLock::new(|| whole(DEVICE_IDENTITY));

fn whole(pattern: &str) -> Regex {
    compiled(&format!(r"\A(?:{pattern})\z"))
}

/// Whether `text` matches `pattern` from its first code point to its last. Every pattern of the module is
/// ASCII, so a text that holds a surrogate matches none.
fn matches(pattern: &Regex, text: &Text) -> bool {
    text.to_str().is_some_and(|text| pattern.is_match(text))
}

/// Whether `text` is a whole [`EPISODE_NAME`].
pub(super) fn is_episode_name(text: &Text) -> bool {
    matches(&EPISODE, text)
}

/// Whether `text` is a whole [`ENVIRONMENT_NAME`].
pub(super) fn is_environment_name(text: &Text) -> bool {
    matches(&ENVIRONMENT, text)
}

/// Whether `text` is a whole PCI vendor and device identity, such as `0x1d0f:0x0061`.
pub(super) fn is_device_identity(text: &Text) -> bool {
    matches(&DEVICE, text)
}
