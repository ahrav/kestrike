//! The service configuration file: one JSON object holding the service's own fields (the state directory, the AWS
//! region, the store table, the listing page bound, the status writer and its key file) beside the fields of
//! `zone_loop::config::ZoneConfig`. Each `ZoneConfig` timer and limit is optional: an absent one takes its owner
//! default, a present one must hold a value of its type (`null` is refused), and the census cap defaults to the
//! directory's shard count at load. [`load`] rejects unknown fields, reads the
//! directory file and the status key file the configuration names, builds the zone listings over the configured
//! region, and returns the first failed check, so a [`Service`] exists only for a configuration whose every file
//! and value passed. The service reads this file and the status key file once, at its start.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use kestrike::failover::records::Host;
use kestrike::failover::report::status::StatusKey;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::config::{
    ConfigRefusal, Fraction, OwnerBounds, ZoneBounds, ZoneConfig,
};
use serde::Deserialize;

use crate::directory::{self, DirectoryError, LayoutFile};
use crate::file::{self, Access, FileError};

pub const FORMAT: u32 = 1;
pub const LIMIT: u64 = 64 << 10;

/// A validated configuration with the status key it names.
pub struct Service {
    /// The state directory, an absolute path.
    pub(crate) state: PathBuf,
    /// The store client's endpoint and limits in the configured region.
    pub(crate) dynamodb: kestrike_aws::Config,
    /// The EC2 clients' endpoint and limits in the configured region.
    pub(crate) ec2: kestrike_aws::Config,
    /// The store's DynamoDB table name: 3 to 255 ASCII letters, digits, `_`, `-` or `.`.
    pub(crate) table: String,
    /// The page bound of each describe action of a zone listing, `kestrike_aws::ec2::ZoneListing::new`'s
    /// `pages`.
    pub(crate) pages: NonZeroU16,
    /// The host number the reconciler status names as its writer.
    pub(crate) writer: Host,
    /// The key derived from the reconciler key the status key file holds.
    pub(crate) status_key: StatusKey,
    /// The validated zone configuration; its `directory` is the fleet directory file's path.
    pub(crate) bounds: ZoneBounds,
}

impl Service {
    /// The state directory, an absolute path.
    pub fn state(&self) -> &Path {
        &self.state
    }
}

#[derive(Debug)]
pub enum ConfigError {
    File(FileError),
    /// A JSON parse or shape error; the message names the line, the column and, for an unknown or missing field,
    /// its name.
    Syntax(String),
    Format(u32),
    /// The named field's value is outside its type.
    Value(&'static str),
    Directory(DirectoryError),
    /// The directory lists another zone than the configuration.
    DirectoryZone {
        config: Zone,
        directory: Zone,
    },
    Zone(ConfigRefusal),
    StatusKey(FileError),
    /// The status key file holds something other than 64 lowercase hexadecimal digits and an optional newline.
    StatusKeyDigits,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(f, "configuration file: {error}"),
            Self::Syntax(error) => write!(f, "configuration file: {error}"),
            Self::Format(format) => {
                write!(f, "configuration file: format {format}, expected {FORMAT}")
            }
            Self::Value(field) => write!(f, "configuration field {field:?}: invalid value"),
            Self::Directory(error) => write!(f, "directory file: {error}"),
            Self::DirectoryZone { config, directory } => write!(
                f,
                "directory file: zone {}, the configuration's zone is {}",
                directory.0, config.0
            ),
            Self::Zone(refusal) => write!(f, "zone configuration refused: {refusal:?}"),
            Self::StatusKey(error) => write!(f, "status key file: {error}"),
            Self::StatusKeyDigits => {
                f.write_str("status key file: expected 64 lowercase hexadecimal digits")
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerFile {
    registrant_max: u32,
    retry_max: u32,
    window: u64,
    report_deadline: u64,
    report_period: u64,
    clock_error: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FractionFile {
    numerator: u32,
    denominator: u32,
}

/// A present optional field: its value decoded as `T`, so an explicit `null` is refused like any other value outside
/// `T`. An absent field takes `#[serde(default)]`'s `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Declares the file's shape: the required fields, then each optional `ZoneConfig` timer and limit, with the
/// function that writes every optional field present over its default. `limits` destructures `ZoneConfig` whole, so
/// a field added to it compiles only once this list names it or the pattern skips it.
macro_rules! config_file {
    ($($field:ident: $ty:ty),+ $(,)?) => {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ConfigFile {
            #[serde(rename = "format")]
            _format: u32,
            state: PathBuf,
            region: String,
            table: String,
            pages: NonZeroU16,
            writer: u64,
            status_key: PathBuf,
            zone: u16,
            name: String,
            directory: PathBuf,
            report_period_us: u64,
            owner: OwnerFile,
            replacement: LayoutFile,
            $(#[serde(default, deserialize_with = "present")] $field: Option<$ty>,)+
            #[serde(default, deserialize_with = "present")]
            host_hold: Option<FractionFile>,
        }

        impl ConfigFile {
            fn limits(&self, config: &mut ZoneConfig) {
                let ZoneConfig {
                    zone: _,
                    name: _,
                    owner: _,
                    replacement: _,
                    directory: _,
                    report_period_us: _,
                    $($field,)+
                    host_hold,
                } = config;
                $(if let Some(value) = self.$field {
                    *$field = value;
                })+
                if let Some(hold) = &self.host_hold {
                    *host_hold = Fraction {
                        numerator: hold.numerator,
                        denominator: hold.denominator,
                    };
                }
            }
        }
    };
}

config_file! {
    tick_us: u64,
    fresh_periods: u32,
    silent_periods: u32,
    stopped_dwell_us: u64,
    impaired_dwell_us: u64,
    absent_ticks: u32,
    loss_ticks: u32,
    attach_settle_us: u64,
    attach_stuck_us: u64,
    detach_settle_us: u64,
    enroll_stuck_us: u64,
    create_settle_us: u64,
    standby_target_us: u64,
    replacements_inflight_max: u32,
    create_attempts_max: u32,
    create_backoff_us: u64,
    create_backoff_max_us: u64,
    enroll_inflight_max: u32,
    attach_starts_per_window: u32,
    attach_window_us: u64,
    standbys_per_host_max: u32,
    population_cap: usize,
    writes_per_tick: u32,
    calls_per_tick: u32,
}

/// A DynamoDB table name: 3 to 255 bytes of ASCII letters, digits, `_`, `-` and `.`.
fn table_name(name: &str) -> bool {
    (3..=255).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// The status key in the file at `path`: the key derived from the reconciler key the file spells.
fn status_key(path: &Path) -> Result<StatusKey, ConfigError> {
    let bytes = file::read(path, 65, Access::Private).map_err(ConfigError::StatusKey)?;
    let digits = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let key = std::str::from_utf8(digits)
        .ok()
        .and_then(file::key)
        .ok_or(ConfigError::StatusKeyDigits)?;
    Ok(StatusKey::derive(&key))
}

/// The service the configuration file at `path` describes.
///
/// # Errors
///
/// The first failed check, in order: the file read ([`ConfigError::File`]), the `format` field, read alone
/// ([`ConfigError::Format`], or [`ConfigError::Syntax`] without one), the JSON shape ([`ConfigError::Syntax`]), the
/// `region`, `table`, `state` and `writer` values ([`ConfigError::Value`]), the directory file
/// ([`ConfigError::Directory`]), its zone ([`ConfigError::DirectoryZone`]), `ZoneConfig::validate`
/// ([`ConfigError::Zone`]), the status key file ([`ConfigError::StatusKey`], [`ConfigError::StatusKeyDigits`]),
/// then the zone listings, which refuse a zone `name` that does not extend the region's name in the shape of an AWS
/// zone name ([`ConfigError::Value`] for `name`).
pub fn load(path: &Path) -> Result<Service, ConfigError> {
    let bytes = file::read(path, LIMIT, Access::Readable).map_err(ConfigError::File)?;
    let format = file::format(&bytes).map_err(|error| ConfigError::Syntax(error.to_string()))?;
    if format != FORMAT {
        return Err(ConfigError::Format(format));
    }
    let parsed: ConfigFile =
        serde_json::from_slice(&bytes).map_err(|error| ConfigError::Syntax(error.to_string()))?;
    let config = |service| kestrike_aws::Config::new(service, &parsed.region);
    let (Some(dynamodb), Some(ec2)) = (config(kestrike_aws::DYNAMODB), config(kestrike_aws::EC2))
    else {
        return Err(ConfigError::Value("region"));
    };
    if !table_name(&parsed.table) {
        return Err(ConfigError::Value("table"));
    }
    if !parsed.state.is_absolute() {
        return Err(ConfigError::Value("state"));
    }
    let writer = Host::new(parsed.writer).ok_or(ConfigError::Value("writer"))?;
    let directory = directory::read(&parsed.directory).map_err(ConfigError::Directory)?;
    let zone = Zone(parsed.zone);
    if directory.zone() != zone {
        return Err(ConfigError::DirectoryZone {
            config: zone,
            directory: directory.zone(),
        });
    }
    let o = &parsed.owner;
    let owner = OwnerBounds {
        registrant_max: o.registrant_max,
        retry_max: o.retry_max,
        window: o.window,
        report_deadline: o.report_deadline,
        report_period: o.report_period,
        clock_error: o.clock_error,
    };
    let replacement = parsed.replacement.layout();
    let mut config = ZoneConfig::defaults(
        zone,
        parsed.name.clone(),
        directory.shards().len(),
        owner,
        replacement,
        parsed.directory.clone(),
        parsed.report_period_us,
    );
    parsed.limits(&mut config);
    let bounds = config.validate().map_err(ConfigError::Zone)?;
    let status_key = status_key(&parsed.status_key)?;
    let service = Service {
        state: parsed.state,
        dynamodb,
        ec2,
        table: parsed.table,
        pages: parsed.pages,
        writer,
        status_key,
        bounds,
    };
    crate::aws::listings(&service).ok_or(ConfigError::Value("name"))?;
    Ok(service)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
