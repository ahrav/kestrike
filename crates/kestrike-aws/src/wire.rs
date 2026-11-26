//! `Wire::send` makes at most one request per call. `Https` implements it
//! over a ureq agent that connects directly to the request host, returns
//! redirect statuses as replies, and keeps at most one idle connection,
//! which a later send reuses while it is younger than `IDLE_AGE`. `Https`
//! accepts a reply body only when the reply frames it with `Content-Length`
//! or chunked transfer coding, and only up to the request's `body_cap`.
//! `Https::new` restricts requests to `https`; the test-only `Https::plain`
//! uses `http`.

use std::error;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use ureq::Agent;
use ureq::http::uri::Authority;
use ureq::http::{Response, StatusCode, Version, header};

use crate::config::MAX_DEADLINE;
use crate::dial::{Dial, Lookup, is_unsent};

/// `IDLE_AGE` bounds the age at which a send still reuses an idle
/// connection.
pub const IDLE_AGE: Duration = Duration::from_secs(5);

/// The header names that control how the body is sent, which `Https::send`
/// derives from the body itself.
pub(crate) const BODY_HEADERS: [&str; 3] = ["content-length", "expect", "transfer-encoding"];

/// One POST to `/` on `host`. `Client::send` fills `headers` with the
/// signed header set, and a `Wire` sends `headers` and `body` unchanged.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// The endpoint authority, `host` or `host:port`. It carries no path,
    /// query or user information.
    pub host: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// The largest reply body the send accepts.
    pub body_cap: usize,
}

/// `Debug` shows the host, the header names, the body length and the body
/// cap, and omits the header values.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Request")
            .field("host", &self.host)
            .field("headers", &names)
            .field("body", &self.body.len())
            .field("body_cap", &self.body_cap)
            .finish()
    }
}

/// A reply of any status, a redirect or an error code included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// `LostAt` is the delivery evidence a lost send carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LostAt {
    /// A refused request or a failed name lookup, connect or TLS handshake.
    Connect,
    /// The send may have written request bytes, so the request may have
    /// reached the service.
    Exchange,
}

/// `kind` names a category: `TimedOut` for a send that reached its
/// deadline, `FileTooLarge` for a reply head or body past its limit,
/// `InvalidData` for a malformed or unframed reply, `InvalidInput` for a
/// request the transport refuses, `NotFound` for a host with no usable
/// address, `WouldBlock` for a lookup refused while the resolver is busy,
/// the I/O error's own kind for other I/O failures, and `Other` for the
/// remaining transport errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lost {
    pub at: LostAt,
    pub kind: io::ErrorKind,
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "send lost at {:?}: {}", self.at, self.kind)
    }
}

impl error::Error for Lost {}

pub trait Wire {
    /// `send` makes at most one HTTP request: a POST of `request` to `/` on
    /// its host, returning at `deadline` plus the slack of the
    /// implementation's blocking waits.
    ///
    /// # Errors
    ///
    /// `send` returns `Lost` if it ends before receiving a complete reply.
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost>;
}

/// `Https` is the production `Wire`. Each send refuses a deadline more than
/// `MAX_DEADLINE` away and sets ureq's global timeout to the time left,
/// sampled after the request is built. A send returns at the deadline plus
/// the slack of its blocking waits: the kernel can end a socket timeout
/// late by up to its timer granularity, ureq gives each connect attempt at
/// least 10 ms and splits the connect time among a host's addresses, and
/// ureq gives each socket write of a body larger than the socket buffer
/// the time left when the body write began.
///
/// The agent resolves the host through `Lookup`, on a helper thread with at
/// most `LOOKUPS` alive, a send that reuses the idle connection included.
/// Each new connection builds its own TLS client configuration and runs a
/// full handshake.
///
/// ureq-proto logs the bytes of each request head, the `authorization`
/// and `x-amz-security-token` values included, and of each reply head and
/// body at `log` level `trace`. A binary that sends through `Https` keeps
/// `trace` off for the `ureq` and `ureq_proto` targets.
pub struct Https {
    agent: Agent,
    scheme: &'static str,
}

impl Https {
    pub fn new() -> Self {
        Self::build(true, Lookup::default())
    }

    #[cfg(test)]
    pub(crate) fn plain() -> Self {
        Self::build(false, Lookup::default())
    }

    #[cfg(test)]
    pub(crate) fn resolving(resolve: fn(&str) -> io::Result<Vec<std::net::SocketAddr>>) -> Self {
        Self::build(false, Lookup::new(resolve))
    }

    fn build(https: bool, lookup: Lookup) -> Self {
        let config = Agent::config_builder()
            .https_only(https)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_idle_connections(1)
            .max_idle_age(IDLE_AGE)
            .build();
        Self {
            agent: Agent::with_parts(config, Dial::default(), lookup),
            scheme: if https { "https" } else { "http" },
        }
    }
}

impl Default for Https {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire for Https {
    fn send(&self, request: &Request<'_>, deadline: Instant) -> Result<Reply, Lost> {
        let refused = |kind| Lost {
            at: LostAt::Connect,
            kind,
        };
        let controls_body = request.headers.iter().any(|(name, _)| {
            BODY_HEADERS
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
        });
        let authority = request
            .host
            .parse::<Authority>()
            .ok()
            .filter(|authority| !authority.as_str().contains('@'));
        let Some(authority) = authority.filter(|_| !controls_body) else {
            return Err(refused(io::ErrorKind::InvalidInput));
        };
        let mut builder = self.agent.post(format!("{}://{authority}/", self.scheme));
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(refused(io::ErrorKind::TimedOut))?;
        if left > MAX_DEADLINE {
            return Err(refused(io::ErrorKind::InvalidInput));
        }
        let mut response = builder
            .config()
            .timeout_global(Some(left))
            .build()
            .send(request.body)
            .map_err(lost)?;
        let cap = u64::try_from(request.body_cap).unwrap_or(u64::MAX);
        let exchange = |kind| Lost {
            at: LostAt::Exchange,
            kind,
        };
        match framing(&response) {
            Framing::Unframed => return Err(exchange(io::ErrorKind::InvalidData)),
            Framing::Length(length) if length > cap => {
                return Err(exchange(io::ErrorKind::FileTooLarge));
            }
            Framing::Length(_) | Framing::Chunked | Framing::Empty => {}
        }
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(cap)
            .read_to_vec()
            .map_err(|error| exchange(lost(error).kind))?;
        Ok(Reply { status, body })
    }
}

enum Framing {
    /// The status carries no body.
    Empty,
    Length(u64),
    Chunked,
    /// The body ends only where the connection closes, so a reset or an
    /// unclean TLS close reads the same as its end.
    Unframed,
}

/// `framing` reads how the reply head delimits the body, by the rules
/// ureq-proto 0.7.1 applies: `chunked` counts as one comma-separated,
/// trimmed, case-insensitive element of a `Transfer-Encoding` value, except
/// on an HTTP/1.0 reply. ureq has already refused `Content-Length` values
/// that disagree, so the first element of the first value stands for all.
fn framing<B>(response: &Response<B>) -> Framing {
    let status = response.status();
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Framing::Empty;
    }
    let headers = response.headers();
    let codings = headers.get_all(header::TRANSFER_ENCODING);
    let chunked = codings
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
    if chunked && response.version() != Version::HTTP_10 {
        return Framing::Chunked;
    }
    // `Transfer-Encoding` takes precedence over `Content-Length` (RFC 9112,
    // section 6.3).
    if codings.iter().next().is_some() {
        return Framing::Unframed;
    }
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .map_or(Framing::Unframed, Framing::Length)
}

/// `lost` classifies a ureq 3.5.2 error raised while the request is sent
/// and its reply head read. `Connect` covers an error `Dial` or `Lookup`
/// marked `Unsent`, an empty address list, and a URI, header or TLS
/// configuration refusal, all raised before the first request byte. Every
/// other error reports `Exchange`.
fn lost(error: ureq::Error) -> Lost {
    use io::ErrorKind;
    use ureq::Error;
    let (at, kind) = match &error {
        Error::Io(io) if is_unsent(io) => (LostAt::Connect, io.kind()),
        Error::HostNotFound => (LostAt::Connect, ErrorKind::NotFound),
        Error::BadUri(_) | Error::Http(_) => (LostAt::Connect, ErrorKind::InvalidInput),
        Error::ConnectionFailed
        | Error::RequireHttpsOnly(_)
        | Error::TlsRequired
        | Error::Tls(_)
        | Error::Rustls(_) => (LostAt::Connect, ErrorKind::Other),
        Error::Timeout(_) => (LostAt::Exchange, ErrorKind::TimedOut),
        Error::Io(io) => (LostAt::Exchange, io.kind()),
        Error::BodyExceedsLimit(_) | Error::LargeResponseHeader(..) => {
            (LostAt::Exchange, ErrorKind::FileTooLarge)
        }
        Error::Protocol(_) => (LostAt::Exchange, ErrorKind::InvalidData),
        _ => (LostAt::Exchange, ErrorKind::Other),
    };
    Lost { at, kind }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
