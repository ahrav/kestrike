//! The lane's close after the controller terminates a case that outlived its declared seconds, read from
//! the hardware manifest the case runs under: the longest `grace` of the cases of the profile's lane role,
//! then the lane's stop and controller windows.
//!
//! [`close_seconds`] reads the manifest's file anew at each call, apart from the checked read the
//! controller makes of the same file, and holds nothing between calls. Its read is the module's one
//! effect.

use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::bounds::member;
use super::error::{Error, Rejected};
use super::seconds::Seconds;
use crate::hardware_lane::{CONTROLLER_SECONDS, STOP_SECONDS};
use crate::host_stop_controller::pure;
use crate::json::{self, Value};
use crate::plants::files::strerror;
use crate::python::{repr, str_of};
use crate::text::{Text, text};

/// `close_seconds` is the seconds the lane's close takes for `profile`: the longest `grace` of the cases
/// of the role its `lane` names, `{"profile": <profile>, "role": <role>}`, in the hardware manifest at
/// `hardware_manifest`, plus [`STOP_SECONDS`] and [`CONTROLLER_SECONDS`]. The path is read in the form
/// [`pure`] gives it, and the manifest's bytes as UTF-8.
///
/// # Errors
///
/// A profile that is no object or holds no `lane`; then a rejection that names the lane after
/// `the hardware manifest names no lane role for `, for a read that fails, written as
/// `[Errno N] <the system's text>: '<path>'`, bytes that are no JSON, and a manifest without that role, or
/// whose role holds no list of cases each with a number under `grace`; and [`Error::Overflow`].
pub fn close_seconds(profile: &Value, hardware_manifest: &Path) -> Result<f64, Error> {
    match longest_grace(profile, hardware_manifest) {
        Ok(grace) => Ok(grace.float()? + STOP_SECONDS + CONTROLLER_SECONDS),
        Err(reason) => Err(Rejected::new(text!(
            "the hardware manifest names no lane role for ",
            str_of(member(profile, "lane")?),
            ": ",
            reason
        ))
        .into()),
    }
}

/// The longest `grace` of the lane role's cases: the first case's, replaced by each later one above it.
fn longest_grace(profile: &Value, hardware_manifest: &Path) -> Result<Seconds, Text> {
    let manifest = read(hardware_manifest)?;
    let profiles = key(&manifest, "profiles")?;
    let lane = key(profile, "lane")?;
    let roles = key(index(profiles, key(lane, "profile")?)?, "roles")?;
    let role = index(roles, key(lane, "role")?)?;
    let Value::Array(cases) = key(role, "cases")? else {
        return Err(Text::from("the role's cases are not a list"));
    };
    let mut longest: Option<Seconds> = None;
    for case in cases {
        let grace = key(case, "grace")?;
        let grace = Seconds::of(grace)
            .ok_or_else(|| text!("a case's grace ", repr(grace), " is not a number"))?;
        longest = Some(match longest {
            Some(current) if !grace.exceeds(&current) => current,
            _ => grace,
        });
    }
    longest.ok_or_else(|| Text::from("the role holds no case"))
}

/// The decoded manifest at the [`pure`] form of `path`.
fn read(path: &Path) -> Result<Value, Text> {
    let path = pure(path.as_os_str().as_bytes());
    let shown = || Text::from_os(path.as_os_str()).repr();
    let mut file = File::open(&path).map_err(|error| system(&error, Some(shown())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        let named = error.kind() == std::io::ErrorKind::IsADirectory;
        system(&error, named.then(shown))
    })?;
    let text = String::from_utf8(bytes).map_err(|_| Text::from("the file is not UTF-8"))?;
    json::parse(&text).map_err(|error| Text::from(error.to_string()))
}

/// A system error as `[Errno N] <the system's text>`, with `: <path>` after it where the error names the
/// file.
fn system(error: &std::io::Error, path: Option<String>) -> Text {
    let mut written = match error.raw_os_error() {
        Some(code) => format!("[Errno {code}] {}", strerror(error)),
        None => error.to_string(),
    };
    if let Some(path) = path {
        written.push_str(": ");
        written.push_str(&path);
    }
    Text::from(written)
}

/// The member `name` of an object, or the key's repr for an absent member.
fn key<'a>(value: &'a Value, name: &str) -> Result<&'a Value, Text> {
    index(value, &Value::String(Text::from(name)))
}

/// The member of an object under the string `name`, or the key's repr for an absent member or a key
/// that is no string.
fn index<'a>(value: &'a Value, name: &Value) -> Result<&'a Value, Text> {
    match (value, name) {
        (Value::Object(object), Value::String(name)) => object
            .get_text(name)
            .ok_or_else(|| Text::from(repr(&Value::String(name.clone())))),
        (Value::Object(_), _) => Err(Text::from(repr(name))),
        _ => Err(text!(
            "a value that is not an object has no member ",
            repr(name)
        )),
    }
}
