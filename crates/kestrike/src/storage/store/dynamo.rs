//! The production store class: one single-region DynamoDB table, read with strongly consistent reads and written
//! with conditional writes on a `ver` attribute that every write raises by one.
//!
//! Writes create an item or replace one conditioned on `ver = expect`. A replacement fails when the item's `ver`
//! differs from `expect`.
//!
//! Replies map to outcomes by the classification the store qualification recorded for this class with one attempt
//! per request: `ConditionalCheckFailedException`, `ValidationException` and `AccessDeniedException` in a 4xx reply
//! never accompany a commit, so they are "not committed"; every other error code, throttling included, and every
//! timeout or transport failure are unknown. The exchange makes at most one attempt per call, because a retried
//! conditional write whose first attempt committed reports `ConditionalCheckFailedException`.

use super::{Item, Key, Outcome, Refusal, Store, Unavailable, Version, Write};
use crate::failover::records::Namespace;

/// A call that returned no success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// A code bare or after its `#` namespace: the service's code from an error reply that cannot follow a commit,
    /// or a refusal code for a write the exchange refused before sending. `classify` reads the code alone, so an
    /// exchange returns `Transport` for a coded reply that can follow a commit, such as a 5xx.
    Error(String),
    /// A connect or read timeout, a transport failure, or a reply the exchange could not use. A write that ends here
    /// may have committed.
    Transport,
}

/// The `pk` prefix (`shard#`, `volume#`, `page#`, `standbys#`, `replacement#`) selects the record codec. An item holds
/// `pk`, `ver`, `val` (the record's encoded bytes) and `wid` (a 16-byte write ID per write request). An implementation
/// writes [`Write::Create`] at `ver = 1` only when `pk` is absent, and [`Write::Exact`] at `ver = expect + 1` only when
/// the item's `ver` is `expect`. An implementation sends at most one request per `get` or `write`.
pub trait Exchange {
    /// `get` returns the item at `key` from a strongly consistent read, or `None` when the table holds no item at
    /// `key`.
    fn get(&mut self, key: &str) -> Result<Option<Item>, Fault>;

    /// The write's conditional call: the `ver` it committed, taken from the store's reply, `ReturnValues = ALL_OLD`
    /// with the old item's `ver + 1`, or 1 when the reply carries no old item.
    fn write(&mut self, key: &str, write: &Write) -> Result<Version, Fault>;

    /// The store-instance identity of the table the exchange read when it was built, with the contract of
    /// `Store::namespace` for that instance. An exchange that addresses its table by name keeps this value after the
    /// name is bound to a restored or repointed table, so its holder builds a new exchange before using the
    /// replacement.
    fn namespace(&self) -> Namespace;
}

/// The production class over the exchange it holds.
pub struct Dynamo<X>(pub X);

impl<X: Exchange> Store for Dynamo<X> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.0.get(&text(key)).map_err(|_| Unavailable)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        match self.0.write(&text(key), write) {
            Ok(version) => Outcome::Committed(version),
            Err(Fault::Error(code)) => classify(&code),
            Err(Fault::Transport) => Outcome::Unknown,
        }
    }

    fn namespace(&self) -> Namespace {
        self.0.namespace()
    }
}

/// Maps an error code to the outcome the store qualification recorded for it.
pub fn classify(code: &str) -> Outcome {
    match code.rsplit_once('#').map_or(code, |(_, bare)| bare) {
        "ConditionalCheckFailedException" => Outcome::NotCommitted(Refusal::Condition),
        "ValidationException" => Outcome::NotCommitted(Refusal::Rejected),
        "AccessDeniedException" => Outcome::NotCommitted(Refusal::Denied),
        _ => Outcome::Unknown,
    }
}

/// The item's `pk`.
pub fn text(key: &Key) -> String {
    match key {
        Key::Shard(shard) => format!("shard#{}", shard.get()),
        Key::Volume(volume) => format!("volume#{}", volume.as_str()),
        Key::Page(shard, page) => format!("page#{}#{page}", shard.get()),
        Key::Standbys(zone) => format!("standbys#{}", zone.0),
        Key::Replacement(shard) => format!("replacement#{}", shard.get()),
    }
}
