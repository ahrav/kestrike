use super::Error;
use super::cli::Args;
use crate::record::HardwareKind;
use crate::store::read_host;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

const FLEET_HOST_CLOSE_SECONDS: f64 = 30.0;
const FIS_KILL_GRACE_SECONDS: f64 = 900.0;
const EXEC_STRING_BOUND: usize = 128 << 10;
const ARGV_BYTES_BOUND: usize = EXEC_STRING_BOUND - 1;
const ROLE_BYTES_BOUND: usize = EXEC_STRING_BOUND - "KESTRIKE_HARDWARE_ROLES=".len() - 1;
const PLATFORM_BYTES_BOUND: usize = EXEC_STRING_BOUND - "KESTRIKE_HARDWARE_PLATFORM=".len() - 1;

pub(super) struct Target {
    pub kind: HardwareKind,
    pub operator: Option<PathBuf>,
    pub cargo: String,
    pub profile: String,
    pub platform: String,
    pub gate: Option<String>,
    pub manifest: PathBuf,
    pub fis_manifest: PathBuf,
    pub custody: Option<PathBuf>,
    pub custody_pin: Option<crate::store::HardwareCustody>,
    pub lane: PathBuf,
    pub fis: PathBuf,
    pub roles: Option<String>,
    pub fleet: Option<Vec<u8>>,
    pub wall: Duration,
    pub grace: Duration,
}

pub(super) fn seconds(value: &str) -> Result<Duration, Error> {
    value
        .parse::<f64>()
        .ok()
        .and_then(|n| Duration::try_from_secs_f64(n).ok())
        .ok_or_else(|| Error::Rejected("duration requires finite nonnegative seconds".into()))
}

fn argument(value: &str) -> Result<(), Error> {
    super::text(value)?;
    if value.len() > ARGV_BYTES_BOUND {
        return Err(Error::Rejected("argument exceeds exec byte bound".into()));
    }
    Ok(())
}

pub(super) fn quoted_lane(lane: &std::path::Path) -> Result<String, Error> {
    Ok(format!(
        "python3 '{}'",
        lane.to_str()
            .ok_or_else(|| Error::Rejected("lane path requires ASCII".into()))?
            .replace('\'', "'\\''")
    ))
}

fn document(path: &std::path::Path) -> Result<(Value, Vec<u8>), Error> {
    let bytes = read_host(path, crate::record::BOUND)
        .map_err(|error| {
            if error.faulted() {
                Error::Unreadable(error)
            } else {
                Error::Rejected(error.to_string())
            }
        })?
        .ok_or_else(|| Error::Rejected(format!("missing {}", path.display())))?;
    let value =
        serde_json::from_slice(&bytes).map_err(|e| Error::Rejected(format!("catalog: {e}")))?;
    Ok((value, bytes))
}

impl Target {
    pub fn parse(args: &Args) -> Result<Self, Error> {
        let profile = args.required("--profile")?.to_owned();
        let operator = args.values.contains_key("--operator");
        let fleet_path = args.values.get("--fleet");
        if operator && fleet_path.is_some() {
            return Err(Error::Rejected(
                "operator and fleet select two controllers".into(),
            ));
        }
        let kind = if operator {
            HardwareKind::Episode
        } else if fleet_path.is_some() {
            HardwareKind::Fleet
        } else {
            HardwareKind::Sweep
        };
        if kind != HardwareKind::Sweep
            && (!args.environments.is_empty() || args.values.contains_key("--cargo"))
        {
            return Err(Error::Rejected(
                "environment and cargo apply to sweep".into(),
            ));
        }
        let manifest = args.path("--manifest", "scripts/hardware-profiles.json")?;
        let fis_manifest = args.path("--fis-manifest", "scripts/fis-profiles.json")?;
        let (catalog, _) = document(&manifest)?;
        let hardware_profile = if operator {
            let (fis, _) = document(&fis_manifest)?;
            fis["profiles"][&profile]["lane"]["profile"]
                .as_str()
                .ok_or_else(|| Error::Rejected("unknown FIS profile".into()))?
                .to_owned()
        } else {
            profile.clone()
        };
        let entry = &catalog["profiles"][&hardware_profile];
        if !entry.is_object() {
            return Err(Error::Rejected("unknown hardware profile".into()));
        }
        let platform = args
            .values
            .get("--platform")
            .cloned()
            .or_else(|| std::env::var("KESTRIKE_HARDWARE_PLATFORM").ok())
            .ok_or_else(|| Error::Rejected("missing platform selection".into()))?;
        if platform.len() > PLATFORM_BYTES_BOUND {
            return Err(Error::Rejected("platform exceeds exec byte bound".into()));
        }
        let row = &catalog["platforms"][&platform];
        let status = entry["platforms"][&platform]
            .as_str()
            .unwrap_or("undeclared");
        let machine = crate::sys::machine()?;
        let supported = row["supported"].as_bool() == Some(true)
            && row["machine"].as_str() == Some(machine.as_str())
            && status == "runs";
        let gate = (!supported).then(|| {
            format!(
                "platform {platform}, status {status}: supported={}, machine={}; host={machine}",
                row["supported"], row["machine"]
            )
        });
        let wall = seconds(args.required("--wall")?)?;
        let (fleet, default_grace) = if let Some(path) = fleet_path {
            let (fleet, bytes) = document(path.as_ref())?;
            if fleet["workload"]["profile"].as_str() != Some(profile.as_str()) {
                return Err(Error::Rejected(
                    "fleet workload names another profile".into(),
                ));
            }
            let hosts = fleet["hosts"]
                .as_object()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::Rejected("fleet requires nonempty hosts".into()))?;
            let grace = fleet["deadlines"]["grace_seconds"]
                .as_f64()
                .filter(|n| n.is_finite() && *n >= 0.0)
                .ok_or_else(|| {
                    Error::Rejected("fleet requires a finite nonnegative grace".into())
                })?;
            (
                Some(bytes),
                Some(2.0 * grace + hosts.len() as f64 * FLEET_HOST_CLOSE_SECONDS),
            )
        } else {
            (None, operator.then_some(FIS_KILL_GRACE_SECONDS))
        };
        let grace = match args.values.get("--grace") {
            Some(value) => seconds(value)?,
            None => Duration::try_from_secs_f64(
                default_grace.ok_or_else(|| Error::Rejected("sweep requires --grace".into()))?,
            )
            .map_err(|_| Error::Rejected("grace exceeds duration range".into()))?,
        };
        let roles = if kind == HardwareKind::Sweep {
            let declared = entry["roles"]
                .as_object()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::Rejected("sweep requires roles".into()))?;
            let ambient = &args.ambient_roles;
            let mut provisioned = std::collections::BTreeMap::new();
            let mut role_bytes = 0usize;
            for role in declared.keys() {
                let label = format!("{hardware_profile}/{role}");
                let matches: Vec<_> = ambient
                    .split_whitespace()
                    .filter(|value| value.split('=').next() == Some(label.as_str()))
                    .collect();
                let length = if ambient.is_empty() {
                    label.len()
                } else if matches.is_empty() {
                    continue;
                } else {
                    matches.iter().map(|value| value.len()).sum::<usize>() + matches.len() - 1
                };
                role_bytes = role_bytes
                    .checked_add(length + 1)
                    .filter(|&bytes| bytes <= ROLE_BYTES_BOUND)
                    .ok_or_else(|| Error::Rejected("expanded roles exceed byte bound".into()))?;
                provisioned.insert(
                    role.clone(),
                    if ambient.is_empty() {
                        label
                    } else {
                        matches.join(" ")
                    },
                );
            }
            let mut seen = std::collections::BTreeSet::new();
            for environment in &args.environments {
                let (role, path) = environment
                    .split_once('=')
                    .ok_or_else(|| Error::Rejected("environment requires ROLE=FILE".into()))?;
                if !std::path::Path::new(path).is_absolute()
                    || environment.chars().any(char::is_whitespace)
                    || !seen.insert(role)
                    || !provisioned.contains_key(role)
                {
                    return Err(Error::Rejected(
                        "environment requires a unique provisioned role and rooted file".into(),
                    ));
                }
                let previous = provisioned
                    .get(role)
                    .expect("provisioned role was checked")
                    .len();
                role_bytes = (role_bytes - previous)
                    .checked_add(hardware_profile.len() + environment.len() + 1)
                    .filter(|&bytes| bytes <= ROLE_BYTES_BOUND)
                    .ok_or_else(|| Error::Rejected("expanded roles exceed byte bound".into()))?;
                provisioned.insert(role.to_owned(), format!("{hardware_profile}/{environment}"));
            }
            if provisioned.is_empty() {
                return Err(Error::Rejected("no provisioned sweep role".into()));
            }
            Some(provisioned.into_values().collect::<Vec<_>>().join(" "))
        } else {
            None
        };
        let operator_path = if operator {
            Some(crate::store::absolute_host(
                args.required("--operator")?.as_ref(),
            )?)
        } else {
            None
        };
        let mut target = Self {
            kind,
            operator: operator_path,
            cargo: args.get("--cargo", "cargo").to_owned(),
            profile,
            platform,
            gate,
            manifest,
            fis_manifest,
            custody: if kind == HardwareKind::Fleet {
                None
            } else {
                Some(PathBuf::from(
                    args.get("--custody", "/var/tmp/kestrike-hardware-custody"),
                ))
            },
            custody_pin: None,
            lane: args.path("--lane", "scripts/hardware-lane.py")?,
            fis: args.path("--fis", "scripts/fis-controller.py")?,
            roles,
            fleet,
            wall,
            grace,
        };
        for value in [&target.profile, &target.platform, &target.cargo]
            .into_iter()
            .chain(target.gate.iter())
            .chain(target.roles.iter())
        {
            argument(value)?;
        }
        let mut paths = vec![&target.manifest, &target.lane];
        if target.kind != HardwareKind::Sweep {
            paths.push(&target.fis_manifest);
        }
        if target.kind == HardwareKind::Episode {
            paths.push(&target.fis);
            argument(&quoted_lane(&target.lane)?)?;
        }
        for path in paths
            .into_iter()
            .chain(target.custody.iter())
            .chain(target.operator.iter())
        {
            argument(
                path.to_str()
                    .ok_or_else(|| Error::Rejected("controller paths require ASCII".into()))?,
            )?;
        }
        if let Some(custody) = &target.custody {
            let map_error = |error: crate::store::Error| match error {
                crate::store::Error::Refused(_) => {
                    Error::Rejected(format!("custody directory: {error}"))
                }
                _ => error.into(),
            };
            crate::store::HardwareCustody::validate_path(custody).map_err(map_error)?;
            if target.gate.is_none() {
                target.custody_pin =
                    Some(crate::store::HardwareCustody::open(custody).map_err(map_error)?);
            }
        }
        Ok(target)
    }
}
