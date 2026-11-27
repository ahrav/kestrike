//! An environment held as a value: the variables a child process is given, in order, which [`get`] reads
//! and [`set`] and [`remove`] change without touching the process's own environment.

use std::ffi::OsString;

/// The variables of an environment as name and value pairs. After [`set`] a name appears once.
pub type Environ = Vec<(OsString, OsString)>;

/// `get` returns the value of the first variable named `name`.
pub fn get<'a>(environ: &'a Environ, name: &str) -> Option<&'a OsString> {
    environ
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

/// `set` removes every variable named `name` and appends `name` with `value`.
pub fn set(environ: &mut Environ, name: &str, value: OsString) {
    environ.retain(|(key, _)| key != name);
    environ.push((OsString::from(name), value));
}

/// `remove` removes every variable named `name`, keeping the others in order.
pub fn remove(environ: &mut Environ, name: &str) {
    environ.retain(|(key, _)| key != name);
}

#[cfg(test)]
#[path = "environ_tests.rs"]
mod tests;
