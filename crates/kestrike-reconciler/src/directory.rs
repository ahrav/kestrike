//! The fleet directory file: one JSON object with the fields of `zone_loop::directory::Listing`, each host's
//! placement inline, and the report key of every listed host. [`read`] rejects unknown fields and checks the
//! listing through `Directory::new`, so a returned directory holds the reconciler projection's report keys only
//! (DERIVED-KEYS-ONLY) and passes ONE-IDENTITY. The file holds keys, so it must be private to the process's user.
//!
//! NO-KEY-TEXT: a [`DirectoryError`] carries no text copied from the file. A parse error names its line and column
//! and, for a missing or repeated field, the field's name from this module's schema; a value error names the field
//! and the host or shard number.

use std::fmt;
use std::path::Path;

use kestrike::failover::arbiter::Partition;
use kestrike::failover::attachments::InstanceId;
use kestrike::failover::records::{Host, Layout};
use kestrike::failover::report::ReportKey;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::directory::{
    Color, DerivedKey, Directory, DirectoryRefusal, DirectoryState, HostEntry, Listing, Placement,
    ReconcilerProjection, ShardEntry,
};
use kestrike::net::ownership::Shard;
use serde::Deserialize;

use crate::file::{self, Access, FileError};

pub const FORMAT: u32 = 1;
pub const LIMIT: u64 = 4 << 20;

#[derive(Debug)]
pub enum DirectoryError {
    File(FileError),
    /// A JSON parse or shape error; the message names the line, the column and, for a missing or repeated field,
    /// its name, and quotes nothing from the file.
    Syntax(String),
    Format(u32),
    /// A host or shard number of zero, a malformed instance ID or a key other than 64 lowercase hexadecimal
    /// digits; the text names the field.
    Value(String),
    Refused(DirectoryRefusal),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(f, "{error}"),
            Self::Syntax(error) => write!(f, "{error}"),
            Self::Format(format) => write!(f, "format {format}, expected {FORMAT}"),
            Self::Value(value) => f.write_str(value),
            Self::Refused(refusal) => write!(f, "refused: {refusal:?}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryFile {
    #[serde(rename = "format")]
    _format: u32,
    version: u64,
    zone: u16,
    zone_hold: bool,
    host_roles_max: u32,
    hosts: Vec<HostFile>,
    shards: Vec<ShardFile>,
    report_keys: Vec<KeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    host: u64,
    instance: String,
    zone: u16,
    partition: u32,
    color: u16,
    state: StateFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum StateFile {
    Active,
    Draining,
    Retired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShardFile {
    shard: u32,
    layout: LayoutFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LayoutFile {
    units: u64,
    slots: u32,
    slot_units: u32,
    entries: u32,
}

impl LayoutFile {
    pub(crate) fn layout(&self) -> Layout {
        Layout {
            units: self.units,
            slots: self.slots,
            slot_units: self.slot_units,
            entries: self.entries,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    host: u64,
    key: String,
}

/// The [`DirectoryError::Syntax`] of `error`. serde's text for a missing or repeated field names a field of the
/// schema, and its text for a syntax error quotes nothing; any other data error, such as a value of the wrong type,
/// an unknown variant or an unknown field, can quote the file, so it is reported by its line and column alone.
fn syntax(error: &serde_json::Error) -> DirectoryError {
    let text = error.to_string();
    let schema = ["missing field `", "duplicate field `"]
        .iter()
        .any(|prefix| text.starts_with(prefix));
    DirectoryError::Syntax(if error.is_data() && !schema {
        format!(
            "a value of the wrong type, an unknown variant or an unknown field at line {} column {}",
            error.line(),
            error.column()
        )
    } else {
        text
    })
}

fn host(value: u64) -> Result<Host, DirectoryError> {
    Host::new(value).ok_or_else(|| DirectoryError::Value("host 0".to_owned()))
}

/// The checked directory in the file at `path`.
///
/// # Errors
///
/// The first failed check, in order: the file read ([`DirectoryError::File`]), the `format` field, read alone
/// ([`DirectoryError::Format`], or [`DirectoryError::Syntax`] without one), the JSON shape
/// ([`DirectoryError::Syntax`]), then in file order each host's number and instance,
/// each shard's number and each key's digits and host ([`DirectoryError::Value`]), then `Directory::new`
/// ([`DirectoryError::Refused`]).
pub fn read(path: &Path) -> Result<Directory<ReconcilerProjection>, DirectoryError> {
    let bytes = file::read(path, LIMIT, Access::Private).map_err(DirectoryError::File)?;
    let format = file::format(&bytes).map_err(|error| syntax(&error))?;
    if format != FORMAT {
        return Err(DirectoryError::Format(format));
    }
    let parsed: DirectoryFile = serde_json::from_slice(&bytes).map_err(|error| syntax(&error))?;
    let zone = Zone(parsed.zone);
    let mut hosts = Vec::with_capacity(parsed.hosts.len());
    for entry in parsed.hosts {
        let host = host(entry.host)?;
        let instance = InstanceId::new(&entry.instance)
            .ok_or_else(|| DirectoryError::Value(format!("the instance of host {}", entry.host)))?;
        hosts.push(HostEntry {
            host,
            instance,
            placement: Placement {
                zone: Zone(entry.zone),
                partition: Partition(entry.partition),
                color: Color(entry.color),
            },
            state: match entry.state {
                StateFile::Active => DirectoryState::Active,
                StateFile::Draining => DirectoryState::Draining,
                StateFile::Retired => DirectoryState::Retired,
            },
        });
    }
    let mut shards = Vec::with_capacity(parsed.shards.len());
    for entry in parsed.shards {
        let shard =
            Shard::new(entry.shard).ok_or_else(|| DirectoryError::Value("shard 0".to_owned()))?;
        shards.push(ShardEntry {
            shard,
            zone,
            layout: entry.layout.layout(),
        });
    }
    let mut keys = Vec::with_capacity(parsed.report_keys.len());
    for entry in parsed.report_keys {
        let key = file::key(&entry.key).ok_or_else(|| {
            DirectoryError::Value(format!("the report key of host {}", entry.host))
        })?;
        keys.push((host(entry.host)?, DerivedKey::Report(ReportKey(key))));
    }
    let listing = Listing {
        version: parsed.version,
        zone,
        zone_hold: parsed.zone_hold,
        host_roles_max: parsed.host_roles_max,
        hosts,
        shards,
    };
    Directory::new(listing, keys).map_err(DirectoryError::Refused)
}
