//! `Imds` authenticates instance metadata requests with an IMDSv2 session
//! token: one `PUT` opens the session, and each `GET` carries its token.
//!
//! Each request runs inside a fixed envelope: it ends by a total deadline
//! measured from before its connect, each connect, write and read waits at
//! most the per-I/O timeout clipped to the time left, and the response,
//! head included, accumulates into one buffer of the byte bound, refused at
//! the first byte past it. The returned body is that same buffer with its
//! head drained, so one owned copy of a response exists at a time.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The instance metadata service's IPv4 address and port.
pub const ENDPOINT: ([u8; 4], u16) = ([169, 254, 169, 254], 80);

/// The envelope one metadata request runs inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The longest one connect, write or read waits.
    pub io: Duration,
    /// The whole request's time from before its connect to its body.
    pub total: Duration,
    /// The most response bytes, head included, the request retains.
    pub bytes: usize,
}

/// The production envelope: 2-second waits, a 6-second request and a
/// 64 KiB response.
///
/// Each field gives the maximum value [`Imds::open`] accepts for the
/// corresponding field of its `limits`.
pub const LIMITS: Limits = Limits {
    io: Duration::from_secs(2),
    total: Duration::from_secs(6),
    bytes: 64 * 1024,
};

/// The instance's metadata, by path below `latest/meta-data/`, shared by
/// the threads that send independent requests at once.
///
/// An implementation returns each body, at most 64 KiB, within one
/// request's 6-second bound, as [`Imds`] does. Discovery waits for every
/// request it starts and checks its own deadline between request rounds,
/// so a provider whose `get` blocks holds discovery until that call
/// returns.
pub trait Metadata: Sync {
    /// The body of `path`.
    ///
    /// # Errors
    ///
    /// `NotFound` for a path the service does not have, or the I/O error of the request.
    fn get(&self, path: &str) -> io::Result<String>;
}

/// The running instance's metadata service, with one session token.
pub struct Imds {
    token: String,
    endpoint: SocketAddr,
    limits: Limits,
}

/// `Debug` output is limited to `endpoint` and `limits`.
impl fmt::Debug for Imds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Imds")
            .field("endpoint", &self.endpoint)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Imds {
    /// Opens a session of `ttl_seconds`.
    ///
    /// # Errors
    ///
    /// As [`Metadata::get`] for [`Imds`], for the token request.
    pub fn connect(ttl_seconds: u32) -> io::Result<Self> {
        Self::open(SocketAddr::from(ENDPOINT), LIMITS, ttl_seconds)
    }

    /// Opens a session of `ttl_seconds` with the service at `endpoint`,
    /// each request inside `limits`.
    ///
    /// # Errors
    ///
    /// `InvalidInput`, before any connection, when a field of `limits` is
    /// zero or exceeds its corresponding field in [`LIMITS`]. Otherwise,
    /// `open` propagates any token request error.
    pub fn open(endpoint: SocketAddr, limits: Limits, ttl_seconds: u32) -> io::Result<Self> {
        let within = |value: Duration, bound: Duration| !value.is_zero() && value <= bound;
        if !(within(limits.io, LIMITS.io)
            && within(limits.total, LIMITS.total)
            && (1..=LIMITS.bytes).contains(&limits.bytes))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let token = request(
            endpoint,
            limits,
            &format!(
                "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: {ttl_seconds}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            ),
        )?;
        Ok(Self {
            token,
            endpoint,
            limits,
        })
    }
}

impl Metadata for Imds {
    /// # Errors
    ///
    /// `TimedOut` when the request passes its total deadline or one wait
    /// passes its per-I/O timeout, `FileTooLarge` for a response longer
    /// than its byte bound, `InvalidData` for a malformed response,
    /// `NotFound` for 404, or the connect or write error.
    fn get(&self, path: &str) -> io::Result<String> {
        request(
            self.endpoint,
            self.limits,
            &format!(
                "GET /latest/meta-data/{path} HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: {}\r\nConnection: close\r\n\r\n",
                self.token
            ),
        )
    }
}

/// Sends one request to `endpoint` inside `limits` and returns the body of
/// a 200 response.
fn request(endpoint: SocketAddr, limits: Limits, text: &str) -> io::Result<String> {
    let deadline = Instant::now() + limits.total;
    // Each wait takes the per-I/O timeout or the time left, whichever is
    // shorter; no time left is the deadline's refusal.
    let wait = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(limits.io))
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut stream = TcpStream::connect_timeout(&endpoint, wait()?)?;
    let mut unsent = text.as_bytes();
    // Each partial write waits on its own timeout, so the deadline is
    // checked before every one.
    while !unsent.is_empty() {
        stream.set_write_timeout(Some(wait()?))?;
        match stream.write(unsent) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => unsent = &unsent[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(timed_out(error)),
        }
    }
    let mut response = vec![0; limits.bytes];
    let mut len = 0;
    loop {
        stream.set_read_timeout(Some(wait()?))?;
        // A full buffer reads into one more byte, which only an over-bound
        // response fills.
        let mut past = [0];
        let into = if len < response.len() {
            &mut response[len..]
        } else {
            &mut past[..]
        };
        match stream.read(into) {
            Ok(0) => break,
            Ok(_) if len == limits.bytes => return Err(io::ErrorKind::FileTooLarge.into()),
            Ok(read) => len += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(timed_out(error)),
        }
    }
    response.truncate(len);
    body(String::from_utf8(response).map_err(|_| io::ErrorKind::InvalidData)?)
}

/// Maps `WouldBlock`, which Linux reports for a socket timeout, to
/// `TimedOut`, and returns every other error unchanged.
fn timed_out(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock => io::ErrorKind::TimedOut.into(),
        _ => error,
    }
}

/// The body of a 200 response, in `response`'s own buffer with the head
/// drained; `NotFound` for a 404.
///
/// The admitted framing: a status line of `HTTP/1.0` or `HTTP/1.1`, a
/// space, exactly three ASCII digits, then a space and a reason or the
/// line's end; header lines of a nonempty name free of spaces and tabs, a
/// colon and a value; every line of the head, the status line included,
/// ended by a CRLF and holding no other CR or LF; the head ending at the
/// first CRLFCRLF; and a body that runs to the end of the stream under the
/// request's `Connection: close`. Every `Content-Length`, matched without
/// regard to case, is a decimal between optional spaces and tabs, equal to
/// the body's length, so differing values, a truncated body and bytes past
/// the declared length all fail it.
///
/// # Errors
///
/// `InvalidData` for a response outside that framing, one carrying a
/// `Transfer-Encoding` header, or a status other than 200 and 404.
pub(super) fn body(mut response: String) -> io::Result<String> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let text = response.as_str();
    let status = line_end(text, 0).ok_or_else(invalid)?;
    let code = status_code(&text[..status]).ok_or_else(invalid)?;
    // Every `Content-Length` must equal the body's length, so the values
    // must agree with one another; the one they share is checked against
    // the body once the head's end is found.
    let mut length = None;
    let mut at = status + 2;
    let start = loop {
        let end = line_end(text, at).ok_or_else(invalid)?;
        if end == at {
            break end + 2;
        }
        let line = &text[at..end];
        let colon = line
            .bytes()
            .position(|byte| matches!(byte, b':' | b' ' | b'\t'))
            .filter(|&colon| colon > 0 && line.as_bytes()[colon] == b':')
            .ok_or_else(invalid)?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = Some(value.trim_matches([' ', '\t']))
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(invalid)?;
            if length.replace(value).is_some_and(|other| other != value) {
                return Err(invalid());
            }
        }
        at = end + 2;
    };
    if length.is_some_and(|length| length != text.len() - start) {
        return Err(invalid());
    }
    match code {
        200 => {
            response.drain(..start);
            Ok(response)
        }
        404 => Err(io::ErrorKind::NotFound.into()),
        _ => Err(invalid()),
    }
}

/// The index of the CRLF that ends the line of `text` starting at `from`,
/// or `None` when the line holds a CR or LF outside that pair or no CRLF
/// follows it.
fn line_end(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = from + memchr::memchr2(b'\r', b'\n', bytes.get(from..)?)?;
    (bytes[end] == b'\r' && bytes.get(end + 1) == Some(&b'\n')).then_some(end)
}

/// The status code of the admitted status line `line`, which holds no CR
/// or LF: `HTTP/1.0` or `HTTP/1.1`, a space, three ASCII digits, then
/// nothing or a space and a reason.
fn status_code(line: &str) -> Option<u16> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))?;
    let (digits, reason) = rest.split_at_checked(3)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit())
        || !(reason.is_empty() || reason.starts_with(' '))
    {
        return None;
    }
    digits.parse().ok()
}
