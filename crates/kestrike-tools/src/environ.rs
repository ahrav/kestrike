//! An environment held as a value: the variables a child process is given, in order, which [`get`] reads
//! and [`set`] and [`remove`] change without touching the process's own environment.

use std::ffi::OsString;
use std::io;
use std::process::Command;

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

/// `check` rejects names containing `=` after the first byte because environment entries use `=` to
/// separate the name from the value.
pub fn check(environ: &[(OsString, OsString)]) -> io::Result<()> {
    for (name, _) in environ {
        if name
            .as_encoded_bytes()
            .iter()
            .skip(1)
            .any(|&byte| byte == b'=')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "illegal environment variable name",
            ));
        }
    }
    Ok(())
}

/// For duplicate names in `environ`, the child receives the first entry's value.
pub fn give(command: &mut Command, environ: &[(OsString, OsString)]) {
    for (name, value) in environ.iter().rev() {
        command.env(name, value);
    }
}

/// `first_of_each` keeps the first variable of each name, the one a lookup of the name reads, the others
/// in order.
pub fn first_of_each(environ: Environ) -> Environ {
    let mut kept: Environ = Vec::with_capacity(environ.len());
    for (name, value) in environ {
        if !kept.iter().any(|(seen, _)| *seen == name) {
            kept.push((name, value));
        }
    }
    kept
}

/// `remove` removes every variable named `name`, keeping the others in order.
pub fn remove(environ: &mut Environ, name: &str) {
    environ.retain(|(key, _)| key != name);
}

#[cfg(test)]
#[path = "environ_tests.rs"]
mod tests;
