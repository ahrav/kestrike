//! The availability withhold of the serving gate: a tenure answers every GET as a miss while its own shard-record
//! read is older than [`W_US`] and an admitted peer in its availability zone reports a successful shard-record read
//! more than [`M_US`] after this tenure's first failed shard-record read since its last success.
//!
//! - AVAILABILITY-ONLY: the rule withholds hits and nothing else; it adds or removes no coverage, validates no
//!   candidate and licenses no step, so its timing carries no safety.
//! - ABSENT-INPUT-WITHHOLDS-NOTHING: an absent own freshness clock, an unset first-failure mark and an absent peer
//!   read time each keep hits serving, which is the store-wide outage behavior: no peer read follows the tenure's
//!   first failed read, except one sent within [`M_US`] before it.
//!
//! All times are microseconds on the suspend-aware serving clock. A failed read counts at its send time; a peer
//! refresh counts at the send time of the observer heartbeat the peer's heartbeat acknowledges minus the
//! freshness-clock age it reports, the earliest time the refresh can have happened.

/// `W`: the own read age past which peer evidence withholds hits.
pub const W_US: u64 = 5_000_000;

/// `M`: one store-read latency plus heartbeat transit, so a peer read sent just before the tenure's failed read
/// withholds nothing.
pub const M_US: u64 = 1_000_000;

/// The withhold's inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Withhold {
    /// The last refresh of the tenure's freshness clock: a shard-record read or own CAS showing the own
    /// `(g, owner, E)`.
    refreshed_at: Option<u64>,
    /// The first-failure mark: the earliest send time among the failed shard-record reads sent after the last
    /// refresh.
    failed_at: Option<u64>,
    /// The latest send time among those failed reads, which a refresh sent between two of them makes the mark.
    latest_failed_at: Option<u64>,
    /// The latest peer refresh time over the admitted heartbeats in the zone that carry a read age and acknowledge one
    /// of the observer's recent heartbeats.
    peer_read_at: Option<u64>,
}

impl Withhold {
    /// The freshness clock refreshed at `at`. A refresh at or after the latest recorded failure clears the mark, one
    /// before the earliest leaves it, and one in between moves it to the latest failure's send time, which errs toward
    /// serving because a failure between the refresh and that time could only make the mark earlier.
    pub fn refresh(&mut self, at: u64) {
        self.refreshed_at = Some(self.refreshed_at.map_or(at, |refreshed| refreshed.max(at)));
        match self.latest_failed_at {
            Some(latest) if at < latest => {
                if self.failed_at.is_some_and(|failed| at >= failed) {
                    self.failed_at = Some(latest);
                }
            }
            _ => {
                self.failed_at = None;
                self.latest_failed_at = None;
            }
        }
    }

    /// A shard-record read sent at `sent_at` timed out or came back unavailable. A failure sent at or before the last
    /// refresh changes nothing; otherwise the mark keeps the earliest send time, in any observation order.
    pub fn failed(&mut self, sent_at: u64) {
        if self.refreshed_at.is_some_and(|at| sent_at <= at) {
            return;
        }
        self.failed_at = Some(self.failed_at.map_or(sent_at, |failed| failed.min(sent_at)));
        self.latest_failed_at = Some(
            self.latest_failed_at
                .map_or(sent_at, |latest| latest.max(sent_at)),
        );
    }

    /// The heartbeat read age at `now`: the time since the freshness clock's last refresh, `None` before the
    /// freshness clock's first refresh or when `now` precedes the last refresh.
    pub fn read_age(&self, now: u64) -> Option<u64> {
        self.refreshed_at.and_then(|at| now.checked_sub(at))
    }

    /// The latest peer read time, `None` with no peer input or no heartbeat carrying a read age.
    pub fn peer(&mut self, read_at: Option<u64>) {
        self.peer_read_at = read_at;
    }

    #[cfg(test)]
    pub(crate) fn failed_at(&self) -> Option<u64> {
        self.failed_at
    }

    #[cfg(test)]
    pub(crate) fn refreshed_at(&self) -> Option<u64> {
        self.refreshed_at
    }

    #[cfg(test)]
    pub(crate) fn peer_read_at(&self) -> Option<u64> {
        self.peer_read_at
    }

    /// Whether a GET hit at `now` answers a miss.
    pub fn withholds(&self, now: u64) -> bool {
        exceeds(now, self.refreshed_at, self.failed_at, self.peer_read_at)
    }
}

/// Withholding requires the own freshness clock's refresh at `refreshed` to be older than [`W_US`] at `now` and the
/// peer refresh to follow `anchor` by more than [`M_US`].
pub(crate) fn exceeds(
    now: u64,
    refreshed: Option<u64>,
    anchor: Option<u64>,
    peer: Option<u64>,
) -> bool {
    match (refreshed, anchor, peer) {
        (Some(refreshed), Some(anchor), Some(peer)) => {
            now.saturating_sub(refreshed) > W_US && peer > anchor.saturating_add(M_US)
        }
        _ => false,
    }
}
