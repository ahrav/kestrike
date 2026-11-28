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

use super::error::{Error, Rejected};
use super::profiles::member;
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
/// [`pure`] gives it, and the manifest's bytes as UTF-8. The lane's names read the manifest as Python's
/// subscript does: a string names a member of an object, and a whole number or a boolean names an item
/// of an array, a negative one counted from its end.
///
/// # Errors
///
/// A profile that is no object or holds no `lane`, whatever the manifest holds; then a rejection that
/// names the lane after `the hardware manifest names no lane role for `, for a read that fails, written
/// as `[Errno N] <the system's text>: '<path>'`, bytes that are no JSON, and a manifest without that role,
/// or whose role holds no list of cases each with a number under `grace`; [`Error::OutOfRange`] for a
/// whole number that names no item of its array or string; and [`Error::Overflow`].
pub fn close_seconds(profile: &Value, hardware_manifest: &Path) -> Result<f64, Error> {
    match longest_grace(profile, hardware_manifest) {
        Ok(grace) => Ok(grace.float()? + STOP_SECONDS + CONTROLLER_SECONDS),
        Err(Miss::OutOfRange) => Err(Error::OutOfRange),
        Err(Miss::Reason(reason)) => Err(Rejected::new(text!(
            "the hardware manifest names no lane role for ",
            str_of(member(profile, "lane")?),
            ": ",
            reason
        ))
        .into()),
    }
}

/// Why the lane role's graces could not be read: a reason the close's rejection gives, or a whole
/// number that names no item.
enum Miss {
    Reason(Text),
    OutOfRange,
}

impl From<Text> for Miss {
    fn from(reason: Text) -> Self {
        Self::Reason(reason)
    }
}

/// The longest `grace` of the lane role's cases: the first case's, replaced by each later one above it.
fn longest_grace(profile: &Value, hardware_manifest: &Path) -> Result<Seconds, Miss> {
    let manifest = read(hardware_manifest)?;
    let profiles = key(&manifest, "profiles")?;
    let lane = key(profile, "lane")?;
    let roles = key(index(profiles, key(lane, "profile")?)?, "roles")?;
    let role = index(roles, key(lane, "role")?)?;
    let Value::Array(cases) = key(role, "cases")? else {
        return Err(Text::from("the role's cases are not a list").into());
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
    longest.ok_or_else(|| Text::from("the role holds no case").into())
}

/// The decoded manifest at the [`pure`] form of `path`.
fn read(path: &Path) -> Result<Value, Text> {
    let path = pure(path.as_os_str().as_bytes());
    let shown = || Text::from_os(path.as_os_str()).repr();
    let mut file = File::open(&path).map_err(|error| system(&error, Some(shown())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        // The open of a directory stands and its read fails, so the read's error names the path.
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

/// The member `name` of an object.
fn key<'a>(value: &'a Value, name: &str) -> Result<&'a Value, Miss> {
    index(value, &Value::String(Text::from(name)))
}

/// `value[name]`: the member of an object under the string `name`, and the item of an array under the
/// whole number or boolean `name`, a negative one counted from the end; the key's repr for an absent
/// member. A string under a whole number in range gives a string of one code point, which no later read
/// takes, so it stands as a reason here.
fn index<'a>(value: &'a Value, name: &Value) -> Result<&'a Value, Miss> {
    match (value, name) {
        (Value::Object(object), Value::String(name)) => object
            .get_text(name)
            .ok_or_else(|| Text::from(repr(&Value::String(name.clone()))).into()),
        (Value::Object(_), _) => Err(Text::from(repr(name)).into()),
        (Value::Array(items), Value::Integer(_) | Value::Bool(_)) => {
            item(items.len(), name).map(|at| &items[at])
        }
        (Value::String(text), Value::Integer(_) | Value::Bool(_)) => {
            item(text.len(), name)?;
            Err(text!("a string has no member ", repr(name)).into())
        }
        _ => Err(text!("a value that is not an object has no member ", repr(name)).into()),
    }
}

/// The place of the whole number or boolean `name` among `count` items, a negative one counted from the
/// end.
fn item(count: usize, name: &Value) -> Result<usize, Miss> {
    let at: i128 = match name {
        Value::Bool(flag) => i128::from(*flag),
        Value::Integer(whole) => whole.to_string().parse().map_err(|_| Miss::OutOfRange)?,
        _ => return Err(Miss::OutOfRange),
    };
    let count = i128::try_from(count).map_err(|_| Miss::OutOfRange)?;
    let at = if at < 0 { at + count } else { at };
    if (0..count).contains(&at) {
        usize::try_from(at).map_err(|_| Miss::OutOfRange)
    } else {
        Err(Miss::OutOfRange)
    }
}
