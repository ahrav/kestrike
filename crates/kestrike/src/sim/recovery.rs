//! The `recovery-cut-v1` record a recovery profile's bundle carries in its
//! Config field, after the profile record: the protocol and format
//! identity, the persistence profile, the attached Identify identity, the
//! cut descriptor's and site registry's hashes, the workload, the
//! activation and the cut bound, as strict text in one canonical order.
//!
//! A manifest profile named `recovery-16k`, `recovery-512` or
//! `recovery-torn` selects a [`Recovery`], whose record the run embeds and
//! whose cut table the
//! chooser admits; every other profile is live and embeds nothing, so a
//! live Config keeps its bytes. A run admits its profile's cut table from
//! the profile name. The loader reads the profile name and the parsed
//! record at the first choice record, and a replay reads them before its
//! first turn; a record that fails to parse, or differs from the one the
//! executable derives for its profile, refuses by its own error.

use sha2::{Digest, Sha256};

use super::action::Profile;
use super::choice::{Admission, TABLE_PREFIX};
use super::cut::{
    Child, Class, Cut, Descriptor, Point, Reach, Site, State, Unit, enumerate, plan, registry,
    registry_hash,
};

/// The record's first line.
const MAGIC: &str = "recovery-cut-v1";

/// The first payload block: past the volume's sixteen-unit metadata prefix.
const PAYLOAD_LBA: u64 = (16 * crate::storage::IO_UNIT / crate::storage::SECTOR) as u64;

/// Blocks of one root slot: the 4096-byte metadata block of the simulated profile.
const ROOT_BLOCKS: u8 = (crate::storage::IO_UNIT / crate::storage::SECTOR) as u8;

/// The record's keys, in canonical order.
pub(crate) const KEYS: [&str; 9] = [
    "protocol",
    "format",
    "profile",
    "identify",
    "descriptor",
    "registry",
    "workload",
    "activation",
    "bound",
];

/// One recovery run's identity, as its bundle's Config field records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) protocol: String,
    pub(crate) format: u16,
    /// The persistence profile, which names the atomic unit declaration.
    pub(crate) profile: String,
    /// The attached device's Identify identity.
    pub(crate) identify: String,
    /// The cut descriptor's SHA-256.
    pub(crate) descriptor: [u8; 32],
    /// The site registry's SHA-256.
    pub(crate) registry: [u8; 32],
    pub(crate) workload: String,
    pub(crate) activation: String,
    /// The most cuts the descriptor enumerates.
    pub(crate) bound: u32,
}

/// Why a record failed to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// The Config field ends before a record's length or bytes, or holds
    /// no profile record ahead of it.
    Absent,
    /// The record failed the frame check: UTF-8 text whose first line is
    /// `recovery-cut-v1` and whose last byte is a newline.
    Magic,
    /// Line `line` is other than its canonical key, ` = ` and a value.
    Syntax { line: usize },
    /// The record ends before `key`.
    Missing { key: &'static str },
    /// Lines follow the last key.
    Trailing,
    /// A live profile's Config field embeds a record that parses: a
    /// recovery bundle relabelled live.
    Live,
    /// The value of `key` is empty, padded, or other than its form: a
    /// decimal integer for `format` and `bound`, 64 lowercase hex digits
    /// for a hash.
    Value { key: &'static str },
}

/// The first field in which a bundle's record differs from the one the
/// executable derives for the bundle's profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mismatch {
    Protocol,
    Format,
    Profile,
    Identify,
    Descriptor,
    Registry,
    Workload,
    Activation,
    Bound,
}

impl Record {
    /// The magic line, then every key in canonical order as `key = value`,
    /// each line ending in a newline; hashes are lowercase hex.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let values = [
            self.protocol.clone(),
            self.format.to_string(),
            self.profile.clone(),
            self.identify.clone(),
            hex(&self.descriptor),
            hex(&self.registry),
            self.workload.clone(),
            self.activation.clone(),
            self.bound.to_string(),
        ];
        let mut out = format!("{MAGIC}\n");
        for (key, value) in KEYS.iter().zip(values) {
            out.push_str(&format!("{key} = {value}\n"));
        }
        out.into_bytes()
    }

    /// Parses `bytes` in the canonical form [`encode`](Self::encode) writes.
    ///
    /// # Errors
    ///
    /// As [`RecordError`].
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let text = std::str::from_utf8(bytes).map_err(|_| RecordError::Magic)?;
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(MAGIC) || !text.ends_with('\n') {
            return Err(RecordError::Magic);
        }
        let mut values = [""; KEYS.len()];
        for (at, key) in KEYS.iter().enumerate() {
            let line = lines.next().ok_or(RecordError::Missing { key })?;
            let value = line
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(" = "))
                .ok_or(RecordError::Syntax { line: at + 2 })?;
            if value.is_empty() || value.trim() != value {
                return Err(RecordError::Value { key });
            }
            values[at] = value;
        }
        if lines.next().is_some() {
            return Err(RecordError::Trailing);
        }
        let number = |at: usize| -> Result<u64, RecordError> {
            let value = values[at];
            match value.parse::<u64>() {
                Ok(number) if number.to_string() == value => Ok(number),
                _ => Err(RecordError::Value { key: KEYS[at] }),
            }
        };
        let hash = |at: usize| unhex(values[at]).ok_or(RecordError::Value { key: KEYS[at] });
        Ok(Self {
            protocol: values[0].to_owned(),
            format: u16::try_from(number(1)?).map_err(|_| RecordError::Value { key: KEYS[1] })?,
            profile: values[2].to_owned(),
            identify: values[3].to_owned(),
            descriptor: hash(4)?,
            registry: hash(5)?,
            workload: values[6].to_owned(),
            activation: values[7].to_owned(),
            bound: u32::try_from(number(8)?).map_err(|_| RecordError::Value { key: KEYS[8] })?,
        })
    }

    /// The first field, in key order, where `self` differs from `expected`.
    ///
    /// # Errors
    ///
    /// That field's [`Mismatch`].
    pub(crate) fn check(&self, expected: &Self) -> Result<(), Mismatch> {
        let differs = [
            (self.protocol != expected.protocol, Mismatch::Protocol),
            (self.format != expected.format, Mismatch::Format),
            (self.profile != expected.profile, Mismatch::Profile),
            (self.identify != expected.identify, Mismatch::Identify),
            (self.descriptor != expected.descriptor, Mismatch::Descriptor),
            (self.registry != expected.registry, Mismatch::Registry),
            (self.workload != expected.workload, Mismatch::Workload),
            (self.activation != expected.activation, Mismatch::Activation),
            (self.bound != expected.bound, Mismatch::Bound),
        ];
        match differs.into_iter().find(|(differs, _)| *differs) {
            Some((_, mismatch)) => Err(mismatch),
            None => Ok(()),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (at, pair) in bytes.chunks(2).enumerate() {
        out[at] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// The Config field's leading bytes for a run of `profile`'s record and,
/// under a recovery profile, `record`: the profile record, then the
/// record's length as a little-endian `u32` and its bytes.
pub(crate) fn embed(profile: Vec<u8>, record: Option<&Record>) -> Vec<u8> {
    let mut out = profile;
    if let Some(record) = record {
        let bytes = record.encode();
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend(bytes);
    }
    out
}

/// The record a recovery run's Config field embeds after its profile
/// record, whose layout [`Profile::record`] owns.
///
/// # Errors
///
/// [`RecordError::Absent`] when `config` ends inside the profile record,
/// the length or the record, else the record's parse error.
pub(crate) fn embedded(config: &[u8]) -> Result<Record, RecordError> {
    let at = Profile::record_len(config).ok_or(RecordError::Absent)?;
    let len = config.get(at..at + 4).ok_or(RecordError::Absent)?;
    let len = u32::from_le_bytes(len.try_into().expect("four bytes")) as usize;
    let bytes = config
        .get(at + 4..at + 4 + len)
        .ok_or(RecordError::Absent)?;
    Record::parse(bytes)
}

/// Whether the manifest profile `name` selects a [`Recovery`].
pub(crate) fn recovery_profile(name: &str) -> bool {
    Recovery::named(name).is_some()
}

/// SHA-256 over each cut's canonical bytes behind their big-endian
/// length, in table order.
pub(crate) fn table_hash(cuts: &[Cut]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for cut in cuts {
        let bytes = cut.canonical();
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

/// Whether a child's landing word is one the simulated device realizes:
/// none, whole, or a prefix of its 512-byte sectors in address order, which
/// its drop and torn-write faults produce. A non-prefix sector mix is
/// outside the supported torn profile.
pub(crate) fn supported(word: u64) -> bool {
    word.trailing_ones() == word.count_ones()
}

/// A recovery profile: the persistence profile a manifest profile name
/// selects, with its descriptor, record and admitted cut table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// 16 KiB atomic units.
    Kib16,
    /// 512-byte atomic units.
    Sector,
    /// The supported torn profile: 512-byte atomic units under process
    /// death and controller reset, whose landings are none, whole or a
    /// sector prefix of the held write. Non-prefix sector mixes,
    /// volatile-cache loss, timeout callbacks and queue-pair failures are
    /// outside it.
    Torn,
}

impl Recovery {
    /// The recovery profile manifest profile `name` selects.
    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            "recovery-16k" => Some(Self::Kib16),
            "recovery-512" => Some(Self::Sector),
            "recovery-torn" => Some(Self::Torn),
            _ => None,
        }
    }

    /// Returns the fill count and the number of 512-byte blocks per fill's
    /// record. Each fill uses one key, and the descriptor declares each
    /// child over this many blocks.
    pub(crate) fn workload(self) -> (usize, u8) {
        match self {
            Self::Kib16 | Self::Sector => (2, 16),
            Self::Torn => (1, 16),
        }
    }

    /// The workload's descriptor, whose children are the device ranges its
    /// fills write: under the two-key workload key 0's 16-block write at
    /// [`PAYLOAD_LBA`] submitted, then key 1's after it while key 0's is
    /// outstanding, under process death; under the torn profile one 16-block
    /// write at [`PAYLOAD_LBA`], two of the simulated profile's 4096-byte
    /// units, so the write can tear, under
    /// process death and controller reset.
    ///
    /// The attach's RESET roots add three recorded points, whose cuts the
    /// table leaves unplanned: `Publication` when slot A's root write is
    /// submitted, `Persistence` when it is persisted, and `RecoveryMutation`
    /// when slot B's root write is submitted after it.
    pub(crate) fn descriptor(self) -> Descriptor {
        let (_, blocks) = self.workload();
        let first = Child {
            lba: PAYLOAD_LBA,
            blocks,
            state: State::Outstanding,
        };
        let second = Child {
            lba: PAYLOAD_LBA + u64::from(blocks),
            ..first
        };
        let point = |operation, before: &[Child], after: &[Child]| Point {
            operation,
            site: Site::Submission as u16,
            occurrence: 0,
            before: before.to_vec(),
            after: after.to_vec(),
        };
        let (classes, mut points, bound) = match self {
            Self::Kib16 | Self::Sector => (
                vec![Class::ProcessDeath],
                vec![
                    point(0, &[], &[first]),
                    point(1, &[first], &[first, second]),
                ],
                70,
            ),
            Self::Torn => (
                vec![Class::ProcessDeath, Class::ControllerReset],
                vec![point(0, &[], &[first])],
                132_895,
            ),
        };
        let slot_a = Child {
            lba: 0,
            blocks: ROOT_BLOCKS,
            state: State::Outstanding,
        };
        let slot_b = Child {
            lba: u64::from(ROOT_BLOCKS),
            ..slot_a
        };
        let persisted = Child {
            state: State::Qualified,
            ..slot_a
        };
        let root = |site: Site, before: &[Child], after: &[Child]| Point {
            site: site as u16,
            ..point(0, before, after)
        };
        points.extend([
            root(Site::Publication, &[], &[slot_a]),
            root(Site::Persistence, &[slot_a], &[persisted]),
            root(Site::RecoveryMutation, &[persisted], &[persisted, slot_b]),
        ]);
        Descriptor {
            unit: match self {
                Self::Kib16 => Unit::Kib16,
                Self::Sector | Self::Torn => Unit::Sector,
            },
            classes,
            reach: vec![
                Reach {
                    site: Site::Submission as u16,
                    required: true,
                },
                Reach {
                    site: Site::Publication as u16,
                    required: false,
                },
                Reach {
                    site: Site::Persistence as u16,
                    required: false,
                },
                Reach {
                    site: Site::RecoveryMutation as u16,
                    required: false,
                },
            ],
            points,
            bound,
        }
    }

    /// The descriptor's cut table: the plan of every enumerated cut at the
    /// fills' `Submission` site whose every landing word is [`supported`].
    ///
    /// # Panics
    ///
    /// When the descriptor or the plan refuses, a defect of this fixture.
    pub(crate) fn table(self) -> Vec<Cut> {
        let descriptor = self.descriptor();
        let cuts: Vec<Cut> = enumerate(&descriptor)
            .expect("a recovery profile's descriptor enumerates")
            .into_iter()
            .filter(|cut| {
                cut.site == Site::Submission as u16 && cut.mask.iter().all(|&word| supported(word))
            })
            .collect();
        plan(&descriptor, &cuts).expect("a recovery profile's supported cuts plan")
    }

    /// The record this executable derives for the profile.
    pub(crate) fn record(self) -> Record {
        let descriptor = self.descriptor();
        Record {
            protocol: "reset-roots".into(),
            format: 1,
            profile: match self {
                Self::Kib16 => "declared-16k".into(),
                Self::Sector => "declared-512".into(),
                Self::Torn => "declared-512-prefix".into(),
            },
            identify: "simulated-unattached".into(),
            descriptor: descriptor.hash(),
            registry: registry_hash(&registry()),
            workload: match self {
                Self::Kib16 | Self::Sector => "two-key".into(),
                Self::Torn => "one-key".into(),
            },
            activation: match self {
                Self::Kib16 | Self::Sector => "process-death-at-stopped-boundary".into(),
                Self::Torn => "process-death-or-reset-at-stopped-boundary".into(),
            },
            bound: descriptor.bound,
        }
    }

    /// The crash candidates the profile's chooser admits: one per cut of
    /// the table, under the table hash's prefix.
    pub(crate) fn admission(self) -> Admission {
        let table = self.table();
        let hash = table_hash(&table);
        Admission {
            cuts: table.len() as u32,
            table: hash[..TABLE_PREFIX].try_into().expect("a prefix"),
        }
    }
}
