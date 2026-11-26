//! `Dial` and `Lookup` are the connector and resolver `Https` builds its
//! agent from. An `Unsent` marker identifies their I/O errors, which arise
//! before the first request byte. `Lookup` keeps at most `LOOKUPS` lookup
//! helpers alive, and a helper counts until its lookup returns.

use std::error;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    ConnectionDetails, Connector, DefaultConnector, NextTimeout, Transport,
};

pub(crate) const LOOKUPS: usize = 4;

/// `Unsent` marks an I/O error raised before the first request byte.
#[derive(Debug)]
struct Unsent;

impl fmt::Display for Unsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the request was not sent")
    }
}

impl error::Error for Unsent {}

fn unsent(kind: io::ErrorKind) -> ureq::Error {
    ureq::Error::Io(io::Error::new(kind, Unsent))
}

pub(crate) fn is_unsent(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Unsent>())
}

/// `Dial` opens a connection through ureq's default TCP and TLS chain. It
/// returns an `Unsent` `TimedOut` error when no connect time is left, and
/// marks each I/O or timeout error from the chain `Unsent`.
#[derive(Debug, Default)]
pub(crate) struct Dial(DefaultConnector);

impl Connector<()> for Dial {
    type Out = Box<dyn Transport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if details.timeout.after.is_zero() {
            return Err(unsent(io::ErrorKind::TimedOut));
        }
        self.0
            .connect(details, chained)
            .map_err(|error| match error {
                ureq::Error::Timeout(_) => unsent(io::ErrorKind::TimedOut),
                ureq::Error::Io(error) => unsent(error.kind()),
                error => error,
            })
    }
}

/// `Lookup` resolves the request host on a helper thread and waits for it
/// for the time ureq allows. An IP-literal host resolves in place. A
/// lookup refused because `LOOKUPS` helpers are alive, a helper that
/// cannot start, a lookup that fails and a wait that times out each return
/// an `Unsent` error.
#[derive(Debug)]
pub(crate) struct Lookup {
    alive: Arc<AtomicUsize>,
    resolve: fn(&str) -> io::Result<Vec<SocketAddr>>,
}

impl Lookup {
    pub(crate) fn new(resolve: fn(&str) -> io::Result<Vec<SocketAddr>>) -> Self {
        Self {
            alive: Arc::default(),
            resolve,
        }
    }
}

impl Default for Lookup {
    fn default() -> Self {
        Self::new(|target| target.to_socket_addrs().map(Iterator::collect))
    }
}

/// `Slot` holds one of a `Lookup`'s helper places until it drops.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Resolver for Lookup {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let target = uri
            .scheme()
            .zip(uri.authority())
            .and_then(|(scheme, authority)| DefaultResolver::host_and_port(scheme, authority))
            .ok_or_else(|| ureq::Error::BadUri(uri.to_string()))?;
        let found = match target.parse::<SocketAddr>() {
            Ok(address) => vec![address],
            Err(_) => self.wait(target, timeout)?,
        };
        let mut addresses = self.empty();
        for address in config.ip_family().keep_wanted(found.into_iter()) {
            if addresses.try_push(address).is_err() {
                break;
            }
        }
        if addresses.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(addresses)
        }
    }
}

impl Lookup {
    fn wait(&self, target: String, timeout: NextTimeout) -> Result<Vec<SocketAddr>, ureq::Error> {
        if self.alive.fetch_add(1, Ordering::SeqCst) >= LOOKUPS {
            self.alive.fetch_sub(1, Ordering::SeqCst);
            return Err(unsent(io::ErrorKind::WouldBlock));
        }
        let slot = Slot(Arc::clone(&self.alive));
        let resolve = self.resolve;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("name lookup".to_owned())
            .spawn(move || {
                let _slot = slot;
                let _ = sender.send(resolve(&target));
            })
            .map_err(|error| unsent(error.kind()))?;
        match receiver.recv_timeout(*timeout.after) {
            Ok(found) => found.map_err(|error| unsent(error.kind())),
            Err(RecvTimeoutError::Timeout) => Err(unsent(io::ErrorKind::TimedOut)),
            Err(RecvTimeoutError::Disconnected) => Err(unsent(io::ErrorKind::Other)),
        }
    }
}
