//! The manifest schema: what one worker run is, as strict text.
//!
//! A manifest is one `key = value` pair per line. Every key below appears
//! exactly once, `version` first; a blank line, an unknown key, a repeated
//! key, a missing key or a value that does not parse rejects the manifest
//! by its own error. The manifest pins the executable's SHA-256, the
//! toolchain and the SHA-256 of the archived build record, names the
//! profile and root seed the run uses, its platform and its scenario,
//! `base` or a reduced one, and carries the CPU feature set as information
//! only. Parsing checks each digest's form. The forms that run, replay or
//! inspect compare the executable and platform with the worker's own;
//! inspection also compares the canonical form with the bundle's recorded
//! manifest, and the canonical form carries the toolchain and build pins
//! into the bundle. Its other keys are the rows of the run's resource
//! contract: the scheduler's actors and turn limits, the disk queue depth,
//! the scripted inputs, the links' copied bytes and retained transmit
//! slots, the rule chain's rules, taps, captures and audit records, the
//! content registry, the upload attempts and source bytes, the incarnation
//! slots, restarts and dead bundles, the suffix tree's depth, children per
//! node, faults and time advances per path, and the recorder's pending
//! buffer, diagnostic ring, record maximum, artifact byte maximum,
//! checkpoint interval and external watchdog seconds.

use super::trace::{Capacity, MAX_BUFFERED, RECORD};

/// The manifest schema version.
pub(crate) const VERSION: u64 = 2;

/// Every key, in canonical order.
pub(crate) const KEYS: [&str; 37] = [
    "version",
    "profile",
    "root",
    "executable",
    "toolchain",
    "build",
    "platform",
    "cpu",
    "scenario",
    "turns",
    "same_time",
    "no_progress",
    "actors",
    "disk_depth",
    "scripted",
    "link_copy_bytes",
    "tx_slots",
    "rules",
    "taps",
    "captures",
    "audit_records",
    "registry",
    "upload_attempts",
    "source_bytes",
    "slots",
    "restarts",
    "bundles",
    "suffix_depth",
    "suffix_children",
    "suffix_faults",
    "suffix_advances",
    "pending",
    "ring",
    "records",
    "bytes",
    "every",
    "watchdog",
];

/// The index in [`KEYS`] of the first count key; `root` before it is also
/// a count.
const FIRST_COUNT: usize = 9;
const _: () = assert!(matches!(KEYS[FIRST_COUNT].as_bytes(), b"turns"));

/// The form a key's value takes, which the worker's capability listing
/// prints. [`Manifest::parse`] reads each count's range from [`form`]; its
/// version, text and digest checks accept the values these forms describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// Exactly [`VERSION`].
    Version,
    /// Nonempty text without surrounding spaces.
    Text,
    /// 64 lowercase hex digits.
    Digest,
    /// Canonical decimal from 1 to `max`.
    Count { max: u64 },
}

/// The form of `key`'s value.
///
/// # Panics
///
/// When `key` names no key of the schema.
pub(crate) fn form(key: &str) -> Form {
    match key {
        "version" => Form::Version,
        "executable" | "build" => Form::Digest,
        "profile" | "toolchain" | "platform" | "cpu" | "scenario" => Form::Text,
        "every" | "watchdog" => Form::Count {
            max: u64::from(u32::MAX),
        },
        "pending" | "ring" => Form::Count { max: MAX_BUFFERED },
        key if key == "root" || KEYS[FIRST_COUNT..].contains(&key) => Form::Count { max: u64::MAX },
        _ => panic!("{key} is no key of the schema"),
    }
}

/// `value` as the count the key `key` holds: canonical decimal, at least 1
/// and at most the maximum its [`Form`] names.
///
/// # Panics
///
/// When `key` is no count of the schema.
pub(crate) fn counted(key: &str, value: &str) -> Option<u64> {
    let Form::Count { max } = form(key) else {
        panic!("{key} is no count");
    };
    value
        .parse::<u64>()
        .ok()
        .filter(|count| (1..=max).contains(count) && value == count.to_string())
}

/// One run's manifest: its pinned and named values, and each count of the
/// resource contract by key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) profile: String,
    pub(crate) root: u64,
    /// The executable's SHA-256, lowercase hex.
    pub(crate) executable: String,
    pub(crate) toolchain: String,
    /// The SHA-256 of the archived build record, lowercase hex. Parsing
    /// checks its form; the canonical form carries it, so the bundle's
    /// leading manifest names that archive.
    pub(crate) build: String,
    pub(crate) platform: String,
    /// The CPU feature set, recorded and never compared.
    pub(crate) cpu: String,
    /// `base` for the profile as named, or the hex encoding of the reduced
    /// scenario a reducer stored.
    pub(crate) scenario: String,
    /// Every count key's value, in [`KEYS`] order after `scenario`.
    counts: [u64; KEYS.len() - FIRST_COUNT],
}

/// Why a manifest was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ManifestError {
    /// Line `line` is not `key = value`.
    Syntax {
        line: usize,
    },
    /// The first line is not `version = ` followed by [`VERSION`]; `found`
    /// is the version it names, `None` when the text is empty or opens with
    /// another key.
    Version {
        found: Option<String>,
    },
    Unknown {
        key: String,
    },
    Duplicate {
        key: &'static str,
    },
    Missing {
        key: &'static str,
    },
    /// The value of `key` is empty, padded with spaces, or not of its
    /// form: a count that is zero or not in canonical decimal, an
    /// `executable` or `build` other than 64 lowercase hex digits, a count
    /// past the maximum its [`Form`] names, or recorder counts no recorder
    /// can honor (see [`Capacity::new`]), which reports `records`.
    Value {
        key: &'static str,
    },
}

impl Manifest {
    /// Parses `text` strictly.
    ///
    /// # Errors
    ///
    /// As [`ManifestError`].
    pub(crate) fn parse(text: &str) -> Result<Self, ManifestError> {
        let mut values: [Option<&str>; KEYS.len()] = [None; KEYS.len()];
        for (at, line) in text.lines().enumerate() {
            let Some((key, value)) = line.split_once(" = ") else {
                return Err(ManifestError::Syntax { line: at + 1 });
            };
            if at == 0 && (key != "version" || value != VERSION.to_string()) {
                return Err(ManifestError::Version {
                    found: (key == "version").then(|| value.to_owned()),
                });
            }
            let slot = KEYS.iter().position(|known| *known == key).ok_or_else(|| {
                ManifestError::Unknown {
                    key: key.to_owned(),
                }
            })?;
            if values[slot].replace(value).is_some() {
                return Err(ManifestError::Duplicate { key: KEYS[slot] });
            }
        }
        if values[0].is_none() {
            return Err(ManifestError::Version { found: None });
        }
        let text = |key: &'static str| -> Result<&str, ManifestError> {
            let slot = KEYS
                .iter()
                .position(|known| *known == key)
                .expect("a schema key");
            let value = values[slot].ok_or(ManifestError::Missing { key })?;
            if value.is_empty() || value.trim() != value {
                return Err(ManifestError::Value { key });
            }
            Ok(value)
        };
        let count = |key: &'static str| -> Result<u64, ManifestError> {
            counted(key, text(key)?).ok_or(ManifestError::Value { key })
        };
        let digest = |key: &'static str| -> Result<&str, ManifestError> {
            let value = text(key)?;
            let hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
            if value.len() != 64 || !value.bytes().all(hex) {
                return Err(ManifestError::Value { key });
            }
            Ok(value)
        };
        let executable = digest("executable")?;
        let build = digest("build")?;
        let mut counts = [0; KEYS.len() - FIRST_COUNT];
        for (slot, key) in KEYS[FIRST_COUNT..].iter().enumerate() {
            counts[slot] = count(key)?;
        }
        let manifest = Self {
            profile: text("profile")?.to_owned(),
            root: count("root")?,
            executable: executable.to_owned(),
            toolchain: text("toolchain")?.to_owned(),
            build: build.to_owned(),
            platform: text("platform")?.to_owned(),
            cpu: text("cpu")?.to_owned(),
            scenario: text("scenario")?.to_owned(),
            counts,
        };
        if manifest.checked_capacity().is_none() {
            return Err(ManifestError::Value { key: "records" });
        }
        Ok(manifest)
    }

    /// The value of count key `key`.
    ///
    /// # Panics
    ///
    /// When `key` names no count of the schema.
    pub(crate) fn count(&self, key: &str) -> u64 {
        self.counts[slot(key)]
    }

    /// Sets count key `key`, for a test that builds one manifest from
    /// another; [`capacity`](Self::capacity) checks the recorder capacity it
    /// implies again.
    ///
    /// # Panics
    ///
    /// As [`count`](Self::count).
    pub(crate) fn with(mut self, key: &str, value: u64) -> Self {
        self.counts[slot(key)] = value;
        self
    }

    /// The manifest's canonical text, every key but `cpu` in schema order,
    /// which the bundle's digest covers; the CPU feature set stays
    /// information.
    pub(crate) fn canonical(&self) -> String {
        let mut out = format!(
            "version = {VERSION}\nprofile = {}\nroot = {}\nexecutable = {}\ntoolchain = {}\nbuild = {}\nplatform = {}\nscenario = {}\n",
            self.profile,
            self.root,
            self.executable,
            self.toolchain,
            self.build,
            self.platform,
            self.scenario
        );
        for (key, value) in KEYS[FIRST_COUNT..].iter().zip(self.counts) {
            out.push_str(&format!("{key} = {value}\n"));
        }
        out
    }

    /// The manifest's full text: its canonical form, then the CPU feature
    /// set.
    pub(crate) fn text(&self) -> String {
        format!("{}cpu = {}\n", self.canonical(), self.cpu)
    }

    /// Parses the canonical form a bundle records, whose CPU feature set it
    /// keeps as a diagnostic, reading the set as `unrecorded`.
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse).
    pub(crate) fn parse_canonical(text: &str) -> Result<Self, ManifestError> {
        Self::parse(&format!("{text}cpu = unrecorded\n"))
    }

    /// The manifest with `scenario` in place of its own.
    pub(crate) fn with_scenario(mut self, scenario: String) -> Self {
        self.scenario = scenario;
        self
    }

    /// The recorder's capacities: the record maximum is the smaller of the
    /// record count and the artifact bytes it fits.
    ///
    /// # Panics
    ///
    /// When [`with`](Self::with) set counts no recorder can honor; a parsed
    /// manifest's always fit.
    pub(crate) fn capacity(&self) -> Capacity {
        self.checked_capacity()
            .expect("the manifest's recorder capacities")
    }

    fn checked_capacity(&self) -> Option<Capacity> {
        let fits = |key| usize::try_from(self.count(key)).ok();
        Capacity::new(
            fits("pending")?,
            fits("ring")?,
            self.count("records")
                .min(self.count("bytes") / RECORD as u64),
            u32::try_from(self.count("every")).ok()?,
        )
    }
}

/// The index of count key `key` among the counts.
fn slot(key: &str) -> usize {
    KEYS[FIRST_COUNT..]
        .iter()
        .position(|known| *known == key)
        .unwrap_or_else(|| panic!("{key} is no count of the schema"))
}
