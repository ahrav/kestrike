//! Context handles archive interruption signals before the build record commits.

use std::cell::Cell;
use std::process::Command;
use std::time::Duration;

use super::{Error, run};
use crate::sys;

pub(super) struct Context {
    signals: sys::Signals,
    interrupted: Cell<Option<i32>>,
}

impl Context {
    pub(super) fn open() -> Result<Self, Error> {
        Ok(Self {
            signals: sys::Signals::open().map_err(|error| Error::Incomplete(error.to_string()))?,
            interrupted: Cell::new(None),
        })
    }

    pub(super) fn check(&self) -> Result<(), Error> {
        if self.interrupted.get().is_none() {
            self.interrupted.set(
                self.signals
                    .take()
                    .map_err(|error| Error::Incomplete(error.to_string()))?,
            );
        }
        match self.interrupted.get() {
            Some(signal) => Err(Error::Interrupted(signal)),
            None => Ok(()),
        }
    }

    pub(super) fn finish<T>(&self, result: Result<T, Error>) -> Result<T, Error> {
        self.check()?;
        result
    }

    pub(super) fn run(
        &self,
        command: &mut Command,
        stderr: run::Stderr,
        deadline: Option<Duration>,
    ) -> Result<run::Ran, run::Failure> {
        run::execute(command, stderr, deadline, Some(self))
    }
}
