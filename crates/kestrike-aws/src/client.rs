//! `Client::send` runs one AWS call under one deadline, `Service::deadline`
//! after the call starts. Credential lookup and `Wire::send` share that
//! deadline. A coded reply, a redirect or an error status included,
//! returns as `Ok`; `Fault` reports a call that ended before receiving a
//! complete reply.

use std::error;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use crate::clock::Clock;
use crate::config::Config;
use crate::credentials::Role;
use crate::sign::{ADDED, Scope, sign};
use crate::wire::{BODY_HEADERS, LostAt, Reply, Request, Wire};

/// One AWS operation: its header names stay distinct from each other and
/// from the names `Client::send` reserves.
#[derive(Debug, Clone, Copy)]
pub struct Call<'a> {
    /// `Fault::action` identifies the failed operation by this name.
    pub action: &'static str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

/// `Stage` is how far a failed call got, as delivery evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The credential refresh failed, and the call ended before
    /// `Wire::send`.
    Credentials,
    /// The call ended before its first request-byte write.
    Connect,
    /// The call may have written request bytes, so the request may have
    /// reached the service, and the call ended before a complete reply
    /// arrived.
    Exchange,
}

/// `Fault` reports a call that ended without a complete reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub action: &'static str,
    pub stage: Stage,
    /// `kind` preserves the `io::ErrorKind` returned by credential lookup
    /// or `Wire::send`.
    pub kind: io::ErrorKind,
    /// The time from the start of the call to the fault: from the start of
    /// `Client::send`, or, for a page of a paged read, from the start of
    /// that page's request.
    pub elapsed: Duration,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed at {:?} after {:?}: {}",
            self.action, self.stage, self.elapsed, self.kind
        )
    }
}

impl error::Error for Fault {}

/// `Client` sends calls to one AWS service endpoint, signed with the
/// instance role's credentials and dated by its `Clock`.
pub struct Client<W, C> {
    config: Config,
    wire: W,
    role: Role,
    clock: C,
}

impl<W: Wire, C: Clock> Client<W, C> {
    pub fn new(config: Config, wire: W, role: Role, clock: C) -> Self {
        Self {
            config,
            wire,
            role,
            clock,
        }
    }

    /// Whether the client signs for the EC2 service, the service
    /// `config::EC2` names.
    pub(crate) fn is_ec2(&self) -> bool {
        self.config.service.name == crate::config::EC2.name
    }

    pub(crate) fn region(&self) -> &str {
        &self.config.region
    }

    /// `send` signs `call` and sends it through the wire with at most one
    /// HTTP request, under one deadline, `Service::deadline` after `send`
    /// starts, which the credential refresh and the wire share. The
    /// signature is dated by the clock reading at which the credentials
    /// were checked unexpired.
    ///
    /// # Errors
    ///
    /// `send` returns a `Stage::Connect` fault of kind `InvalidInput`,
    /// before any credential or network request, when two names in
    /// `call.headers` match after ASCII lowercasing or a lowercased name is
    /// one `sign` adds (`authorization`, `host`, `x-amz-date`,
    /// `x-amz-security-token`) or one in `BODY_HEADERS`. The wire controls
    /// request-body framing. `send` returns a `Stage::Credentials` fault,
    /// before `Wire::send`, when credential lookup returns an error, with
    /// that error's kind, and a `Stage::Connect` fault of kind `TimedOut`,
    /// before signing, when the deadline has passed once credentials are
    /// chosen. For a `Wire::send` error, `Fault::stage` carries the wire's
    /// delivery evidence and `Fault::kind` the wire's error kind.
    pub fn send(&mut self, call: &Call<'_>) -> Result<Reply, Fault> {
        let start = Instant::now();
        self.send_from(call, start, start + self.config.service.deadline)
    }

    /// The instant `Service::deadline` from now. `Config::new` bounds the
    /// deadline by `MAX_DEADLINE`, so the sum stays representable.
    pub(crate) fn deadline_from_now(&self) -> Instant {
        Instant::now() + self.config.service.deadline
    }

    /// `send_until` is `send` under `deadline`, an instant
    /// `deadline_from_now` returned, so the pages of one paged read share
    /// the read's deadline. A `deadline` later than `Service::deadline`
    /// after the call starts is cut to that instant.
    pub(crate) fn send_until(
        &mut self,
        call: &Call<'_>,
        deadline: Instant,
    ) -> Result<Reply, Fault> {
        let start = Instant::now();
        let limit = start + self.config.service.deadline;
        self.send_from(call, start, deadline.min(limit))
    }

    /// `send_from` sends `call` under `deadline` and measures
    /// `Fault::elapsed` from `start`.
    fn send_from(
        &mut self,
        call: &Call<'_>,
        start: Instant,
        deadline: Instant,
    ) -> Result<Reply, Fault> {
        let fault = |stage, kind| Fault {
            action: call.action,
            stage,
            kind,
            elapsed: start.elapsed(),
        };
        let mut names: Vec<String> = call
            .headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .chain(
                ADDED
                    .iter()
                    .chain(&BODY_HEADERS)
                    .map(|name| (*name).to_owned()),
            )
            .collect();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(fault(Stage::Connect, io::ErrorKind::InvalidInput));
        }
        let (keys, now) = self
            .role
            .keys(&self.clock, deadline)
            .map_err(|kind| fault(Stage::Credentials, kind))?;
        if Instant::now() >= deadline {
            return Err(fault(Stage::Connect, io::ErrorKind::TimedOut));
        }
        let scope = Scope {
            region: &self.config.region,
            service: self.config.service.name,
        };
        let headers = sign(keys, scope, now, &self.config.host, call.headers, call.body);
        let request = Request {
            host: &self.config.host,
            headers: &headers,
            body: call.body,
            body_cap: self.config.service.body_cap,
        };
        self.wire.send(&request, deadline).map_err(|lost| {
            let stage = match lost.at {
                LostAt::Connect => Stage::Connect,
                LostAt::Exchange => Stage::Exchange,
            };
            fault(stage, lost.kind)
        })
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
