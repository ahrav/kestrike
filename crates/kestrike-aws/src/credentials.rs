//! `Role` obtains instance-role credentials through IMDSv2. `Role::keys`
//! attempts one refresh per call when credentials are absent, expired, or
//! valid for less than `REFRESH_MARGIN`, and keeps unexpired credentials in
//! use when the refresh fails. A call that holds unexpired credentials
//! skips the refresh when the last refresh attempted was under the same
//! deadline, so the pages of one paged read attempt at most one refresh
//! while their credentials stay unexpired; a call that holds none always
//! attempts one. The caller waits for the refresh for at
//! most `REFRESH_WAIT` clipped to the call's deadline; while it holds
//! unexpired credentials it waits for at most half the time left, so the
//! send keeps the other half. `keys` checks the credentials it returns
//! against one clock reading and returns that reading for signing.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use kestrike::bind::{ENDPOINT, Imds, LIMITS, Limits, Metadata};

use crate::clock::{Clock, parse_utc};
use crate::sign::Keys;

/// A call refreshes when less than `REFRESH_MARGIN` of the held
/// credentials' lifetime remains, unless the last refresh attempted was
/// under the same deadline.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(10 * 60);

/// The longest a call waits for a refresh.
pub const REFRESH_WAIT: Duration = Duration::from_millis(500);

/// Each refresh opens its own session with this lifetime in seconds.
const TOKEN_TTL: u32 = 60;

const LISTING: &str = "iam/security-credentials/";

/// `Role` holds the instance role's latest credentials and refreshes them
/// from the IMDSv2 service at its endpoint.
#[derive(Debug)]
pub struct Role {
    endpoint: SocketAddr,
    held: Option<Held>,
    /// The deadline of the last refresh attempted.
    attempted: Option<Instant>,
}

#[derive(Debug)]
struct Held {
    keys: Keys,
    expiry: SystemTime,
}

impl Held {
    /// `remaining` is zero from `expiry` on.
    fn remaining(&self, now: SystemTime) -> Duration {
        self.expiry.duration_since(now).unwrap_or_default()
    }
}

impl Role {
    /// `Role::instance` reads credentials from the instance metadata
    /// service at `bind::ENDPOINT`. The first `Client::send` fetches them.
    pub fn instance() -> Self {
        Self::at(SocketAddr::from(ENDPOINT))
    }

    /// `at` reads credentials through IMDSv2 from the service at
    /// `endpoint`.
    pub(crate) fn at(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            held: None,
            attempted: None,
        }
    }

    /// `keys` returns the credentials to sign with and the clock reading
    /// at which they are unexpired. It drops held credentials that
    /// `clock`'s first reading finds expired, and refreshes once when no
    /// credentials are held or their remaining lifetime is less than
    /// `REFRESH_MARGIN` at that reading. With unexpired credentials held,
    /// it skips the refresh when the last refresh attempted was under the
    /// same `deadline`. After a refresh it reads `clock` again and checks
    /// the credentials against that reading.
    ///
    /// # Errors
    ///
    /// `keys` returns the refresh's error kind, `InvalidData` for a fetched
    /// document already expired, when the refresh fails and no unexpired
    /// credentials remain at the reading taken after it. It then drops the
    /// expired credentials.
    pub(crate) fn keys(
        &mut self,
        clock: &impl Clock,
        deadline: Instant,
    ) -> Result<(&Keys, SystemTime), io::ErrorKind> {
        let mut now = clock.now();
        if self
            .held
            .as_ref()
            .is_some_and(|held| held.remaining(now).is_zero())
        {
            self.held = None;
        }
        let left = self.held.as_ref().map(|held| held.remaining(now));
        let attempted = left.is_some() && self.attempted == Some(deadline);
        if left.is_none_or(|left| left < REFRESH_MARGIN) && !attempted {
            self.attempted = Some(deadline);
            let refreshed = fetch(self.endpoint, deadline, left.is_some());
            now = clock.now();
            match refreshed.and_then(|held| {
                if held.remaining(now).is_zero() {
                    Err(io::ErrorKind::InvalidData)
                } else {
                    Ok(held)
                }
            }) {
                Ok(held) => self.held = Some(held),
                Err(kind)
                    if self
                        .held
                        .as_ref()
                        .is_none_or(|held| held.remaining(now).is_zero()) =>
                {
                    self.held = None;
                    return Err(kind);
                }
                Err(_) => {}
            }
        }
        let held = self
            .held
            .as_ref()
            .expect("a successful refresh or an unexpired fallback leaves credentials held");
        Ok((&held.keys, now))
    }
}

/// `fetch` reads the role name and then its credential document through
/// one IMDSv2 session on a helper thread, and waits for the helper's
/// result until a cutoff `refresh_wait` after the call to `fetch`. Each of
/// the helper's three requests, the session token, the listing and the
/// document, may take the whole wait, and the helper checks the cutoff
/// before it starts each one. A request already started can run on for up
/// to one wait after `fetch` returns.
fn fetch(endpoint: SocketAddr, deadline: Instant, held: bool) -> Result<Held, io::ErrorKind> {
    let start = Instant::now();
    let wait = refresh_wait(deadline.saturating_duration_since(start), held);
    if wait.is_zero() {
        return Err(io::ErrorKind::TimedOut);
    }
    let cutoff = start + wait;
    let limits = Limits {
        io: wait,
        total: wait,
        bytes: LIMITS.bytes,
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("credential refresh".to_owned())
        .spawn(move || {
            let _ = sender.send(read(endpoint, limits, cutoff));
        })
        .map_err(|error| error.kind())?;
    collect(&receiver, cutoff)
}

/// `refresh_wait` is `REFRESH_WAIT` clipped to `left`, the time before the
/// call's deadline, or to half of `left` when `held` says unexpired
/// credentials remain, so the send keeps the other half.
fn refresh_wait(left: Duration, held: bool) -> Duration {
    if held { left / 2 } else { left }.min(REFRESH_WAIT)
}

/// `collect` waits for the helper's result until `cutoff`. It returns
/// `TimedOut` when the cutoff passes first and `Other` when the helper
/// ends without sending a result.
fn collect(
    receiver: &mpsc::Receiver<Result<Held, io::ErrorKind>>,
    cutoff: Instant,
) -> Result<Held, io::ErrorKind> {
    receiver
        .recv_timeout(cutoff.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
            RecvTimeoutError::Disconnected => io::ErrorKind::Other,
        })?
}

/// `read` requires exactly one role in the listing and uses `is_role_name`
/// to validate its name as a single path segment before appending it to
/// `LISTING`. It starts each metadata request only before `cutoff`.
fn read(endpoint: SocketAddr, limits: Limits, cutoff: Instant) -> Result<Held, io::ErrorKind> {
    let kind = |error: io::Error| error.kind();
    let before_cutoff = || {
        if Instant::now() < cutoff {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut)
        }
    };
    before_cutoff()?;
    let imds = Imds::open(endpoint, limits, TOKEN_TTL).map_err(kind)?;
    before_cutoff()?;
    let listing = imds.get(LISTING).map_err(kind)?;
    let mut lines = listing.lines();
    let role = lines
        .next()
        .filter(|role| is_role_name(role))
        .ok_or(io::ErrorKind::InvalidData)?;
    if lines.any(|line| !line.is_empty()) {
        return Err(io::ErrorKind::InvalidData);
    }
    before_cutoff()?;
    let document = imds.get(&format!("{LISTING}{role}")).map_err(kind)?;
    parse(&document).ok_or(io::ErrorKind::InvalidData)
}

fn is_role_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@_-".contains(&byte))
}

fn parse(document: &str) -> Option<Held> {
    let value: serde_json::Value = serde_json::from_str(document).ok()?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_graphic()))
    };
    if field("Code")? != "Success" {
        return None;
    }
    Some(Held {
        keys: Keys {
            access_key_id: field("AccessKeyId")?.to_owned(),
            secret_access_key: field("SecretAccessKey")?.to_owned(),
            session_token: Some(field("Token")?.to_owned()),
        },
        expiry: parse_utc(field("Expiration")?)?,
    })
}

#[cfg(test)]
impl Role {
    /// `holding` holds `keys` until `expiry` and refreshes from the service
    /// at `endpoint`. A call whose clock reads at least `REFRESH_MARGIN`
    /// before `expiry` signs with `keys` and sends no metadata request.
    pub(crate) fn holding(keys: Keys, expiry: SystemTime, endpoint: SocketAddr) -> Self {
        Self {
            held: Some(Held { keys, expiry }),
            ..Self::at(endpoint)
        }
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
