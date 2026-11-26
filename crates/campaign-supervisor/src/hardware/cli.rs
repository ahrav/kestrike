use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use super::{Error, runs, target, text};
use crate::exit::Supervisor;
use crate::store::{Store, View};

pub fn run(args: &[OsString]) -> Supervisor {
    match execute(args) {
        Ok((value, exit)) => {
            let _ = writeln!(std::io::stdout(), "{value}");
            exit
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "campaign hardware: {error}");
            error.exit()
        }
    }
}

pub(super) struct Args {
    pub values: BTreeMap<String, String>,
    pub environments: Vec<String>,
    pub ambient_roles: String,
}

impl Args {
    fn parse(command: &str, args: &[OsString]) -> Result<Self, Error> {
        let allowed = match command {
            "run" => &[
                "--state",
                "--profile",
                "--wall",
                "--grace",
                "--operator",
                "--fleet",
                "--manifest",
                "--fis-manifest",
                "--lane",
                "--fis",
                "--custody",
                "--cargo",
                "--platform",
            ][..],
            "dispose" => &["--state", "--run", "--evidence"][..],
            _ => return Err(Error::Rejected("expected run or dispose".into())),
        };
        if !args.len().is_multiple_of(2) {
            return Err(Error::Rejected("options require values".into()));
        }
        let mut parsed = Self {
            values: BTreeMap::new(),
            environments: Vec::new(),
            ambient_roles: if command == "run" {
                match std::env::var("KESTRIKE_HARDWARE_ROLES") {
                    Ok(value) => value,
                    Err(std::env::VarError::NotPresent) => String::new(),
                    Err(std::env::VarError::NotUnicode(_)) => {
                        return Err(Error::Rejected(
                            "KESTRIKE_HARDWARE_ROLES requires UTF-8".into(),
                        ));
                    }
                }
            } else {
                String::new()
            },
        };
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0]
                .to_str()
                .ok_or_else(|| Error::Rejected("option requires ASCII".into()))?;
            let value = pair[1]
                .to_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| Error::Rejected("option requires nonempty text".into()))?;
            text(value)?;
            if key == "--environment" && command == "run" {
                parsed.environments.push(value.to_owned());
            } else if !allowed.contains(&key)
                || parsed
                    .values
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err(Error::Rejected(format!("unknown or repeated {key}")));
            }
        }
        Ok(parsed)
    }
    pub fn required(&self, key: &str) -> Result<&str, Error> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| Error::Rejected(format!("missing {key}")))
    }
    pub fn get<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.values.get(key).map(String::as_str).unwrap_or(default)
    }
    pub fn path(&self, key: &str, default: &str) -> Result<PathBuf, Error> {
        crate::store::absolute_host(self.get(key, default).as_ref()).map_err(Error::from)
    }
}

fn hardware_store(state: &std::path::Path, initialize: bool) -> Result<(Store, View), Error> {
    let limit = crate::sys::controller_file_limit()?;
    let minimum = crate::store::MARKER_BYTES.len() as u64;
    if limit < minimum {
        return Err(Error::Rejected(format!(
            "hardware state requires a file-size hard limit of at least {minimum} bytes"
        )));
    }
    let bytes = state.as_os_str().as_encoded_bytes();
    if bytes
        .split(|byte| *byte == b'/')
        .skip(usize::from(state.is_absolute()))
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(Error::Rejected(
            "state path requires canonical components".into(),
        ));
    }
    crate::store::given_ancestors(state).map_err(Error::input_path)?;
    if initialize {
        crate::store::create_dirs(state)?;
    }
    let view = crate::store::View::open(state)?;
    match view.require_state_marker() {
        Ok(()) => {}
        Err(crate::store::Error::Refused(crate::store::Refusal::Unmarked)) if initialize => {
            drop(Store::open(state)?);
        }
        Err(error) => return Err(error.into()),
    }
    let hardware = view.path().join("hardware");
    if initialize {
        match crate::store::create_dir(&hardware) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
    } else {
        if view
            .open_dir(view.root(), &super::name("hardware"))?
            .is_none()
        {
            return Err(Error::Rejected("hardware run absent".into()));
        }
        crate::store::View::open(&hardware)?.require_state_marker()?;
    }
    Ok((Store::open(&hardware)?, view))
}

fn execute(args: &[OsString]) -> Result<(serde_json::Value, Supervisor), Error> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| Error::Rejected("expected hardware action".into()))?;
    let command = command.to_str().unwrap_or("");
    let args = Args::parse(command, rest)?;
    let state = PathBuf::from(args.required("--state")?);
    if command == "dispose" {
        let number = args
            .required("--run")?
            .parse::<u64>()
            .map_err(|_| Error::Rejected("run requires an integer".into()))?;
        if number == 0 {
            return Err(Error::Rejected("run requires a positive integer".into()));
        }
        let disposition =
            crate::record::HardwareDisposition::new(number, text(args.required("--evidence")?)?)
                .ok_or_else(|| {
                    Error::Rejected("a disposition requires nonblank evidence".into())
                })?;
        let (store, _) = hardware_store(&state, false)?;
        runs::reconcile(&store)?;
        let creation = runs::dispose(&store, disposition)?;
        return Ok((
            serde_json::json!({"run": number, "disposed": true, "recorded": creation == crate::store::Creation::Created}),
            Supervisor::Success,
        ));
    }
    let (store, parent) = hardware_store(&state, true)?;
    runs::admit(&store)?;
    runs::campaign_headroom(&parent)?;
    let target = target::Target::parse(&args)?;
    let record = super::controller::run(&store, target)?;
    let exit = if record.class == Some(crate::record::HardwareClass::Held) {
        Supervisor::Held
    } else {
        Supervisor::Success
    };
    Ok((serde_json::json!(record), exit))
}
