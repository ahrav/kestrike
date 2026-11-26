//! The recovery I/O share: the device bytes one host's recovery may issue per interval, split evenly over the host's
//! owners, and each owner's accounting of its part.
//!
//! HOST-SHARE: a [`HostShare`] names the host's recovery bytes per interval and the number of owners the host runs.
//! Each owner's [`IoShare`] is a bucket: it holds the bytes the owner charged, drains the owner's part,
//! `bytes / owners`, over each interval of the clock, and admits a charge while the bytes it holds stay within its
//! capacity. In any span of `t` ticks an owner therefore charges at most its capacity plus `part * t / interval`
//! bytes. The capacity is the largest bulk charge, the [`RESERVE`] and a slack, and at most the part. The slack is
//! the part's drain over `1 / SLACK` of an interval, or over one tick of an interval shorter than `SLACK` ticks, so
//! an owner whose capacity is below its part and whose polls fall at most that far apart charges at the part's rate
//! under demand above it. One poll charges at most the capacity, so an owner whose polls fall more than
//! `capacity * interval / part` ticks apart, the time the capacity takes to drain, charges less than its part. While
//! the host runs at most `owners` owners under one `HostShare`, and no owner attaches again within one interval of
//! its previous attach's last charge, the charges all its owners make in any span of one interval sum to at most
//! `bytes` plus the owners' capacities, which is at most `2 * bytes`. Each share starts with an empty bucket at its
//! attach, so an owner that attaches again inside that interval adds up to its capacity. The owner count and the
//! attach cadence are the operator's configuration of the host, which each share takes as given; an owner started
//! beyond the count adds its own part and capacity.
//!
//! SHARE-BEFORE-ISSUE: the share charges a named slot's window and suffix-run reads, and checkpoint-unit writes and
//! read-backs, each its byte length as the volume submits it to the device, and suffix-block writes as the suffix log
//! hands one out for writing. A command the bucket cannot hold stays staged with
//! its buffer and is offered again at a later tick, and a command the device turns away returns its charge, so each
//! charged metadata command the device accepts was charged at the tick it was accepted. The attach's two root probes
//! and its RESET roots, with each failed root write retried up to `metadata_retries` times, so at most
//! `2 + 2 * (1 + metadata_retries)` blocks per attach, run outside it. A charge is for issue: the bucket drains with
//! the clock alone, so a command that stalls, fails or never completes holds its bytes only until they drain, and the
//! bucket is empty one interval after its last charge.
//!
//! SUFFIX-RESERVE: bulk charges (reads and checkpoint units) leave [`RESERVE`] bytes of the capacity unspent, which
//! only suffix blocks take, so with a checkpoint or a load taking all the bulk room, a suffix block is refused only
//! while the reserve drains from the suffix block before it, `RESERVE * interval / part` ticks and at most one
//! interval. The reserve is one block whatever the interval and the suffix log's flush period: a log that seals blocks
//! faster than that drains one block per such span, and its queue and age caps refuse appends before acknowledgment.
//! A suffix block may also take bulk room, so sustained suffix demand defers bulk charges and the checkpoints they
//! carry; the delta region then fills and the log refuses appends before acknowledgment. Attach refuses an owner part
//! that holds less than its largest bulk charge plus the reserve, so every charge fits an empty bucket.
//!
//! SHARE-REPORT: beside the bucket the share counts its charges in windows, for the recovery report and the pressure
//! gauge. The first window opens at the first charge offered, and each later one at the first charge offered at least
//! `interval` ticks after the previous window opened, whether the bucket holds or refuses that charge. A window
//! counts as saturated once it refuses a charge, one the bucket could not hold when it was offered. A saturated
//! window reads full until it is `interval` ticks old, whether or not the bucket drained since.
//!
//! One `IoShare` exists per owner: its volume's attach builds it and moves it into the volume, and `IoShare` is a
//! move-only type, so that volume holds the owner's single budget.

/// The bytes of the capacity a bulk charge leaves to suffix blocks: one delta block.
pub(crate) const RESERVE: u64 = super::delta::UNIT_LEN as u64;

/// The host's recovery I/O share: `bytes` per `interval` for the whole host, split evenly over its `owners`, each
/// owner draining `bytes / owners` per `interval` ticks from a bucket of at most that many bytes. While the host runs
/// at most `owners` owners, none attaching again within one interval of its previous attach's last charge, the
/// owners' charges in any span of one interval sum to at most `bytes` plus the owners' bucket capacities, at most
/// `2 * bytes`. Root probes and root writes, at most `2 + 2 * (1 + metadata_retries)` blocks per attach, run outside
/// the share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostShare {
    /// The host's recovery device bytes per interval, across all its owners.
    pub bytes: u64,
    /// The span each owner's part drains over, in ticks of the `now` every owner's volume polls read. Each owner on the
    /// host polls with one nondecreasing clock of the same unit and rate; the owner's poll and the soak pass
    /// microseconds.
    pub interval: u64,
    /// The owners the host runs, each under this share; 1 to [`MAX_OWNERS`] (128).
    pub owners: u32,
}

/// The most owners one host runs: one per volume, at most the volumes one host report holds.
pub const MAX_OWNERS: u32 = crate::failover::report::MAX_ENTRIES as u32;

impl HostShare {
    /// One owner's part: `bytes / owners` per `interval`, or `None` for a zero interval, no owner, more than
    /// [`MAX_OWNERS`] owners, or a part below `largest` bulk bytes plus [`RESERVE`].
    pub(crate) fn part(self, largest: u64) -> Option<u64> {
        if self.interval == 0 || self.owners > MAX_OWNERS {
            return None;
        }
        let part = self.bytes.checked_div(u64::from(self.owners))?;
        (part >= largest.saturating_add(RESERVE)).then_some(part)
    }
}

/// What a charge is for: bulk is a recovery read or a checkpoint-unit command, and a suffix block may take the
/// capacity's reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoClass {
    Bulk,
    Suffix,
}

/// The divisor of the interval whose drain is the capacity's slack; HOST-SHARE states what the slack holds.
const SLACK: u64 = 64;

/// One owner's recovery I/O accounting; see the module documentation.
#[derive(Debug)]
pub(crate) struct IoShare {
    part: u64,
    interval: u64,
    /// The charged bytes the bucket holds, in byte-ticks: each charge adds its bytes times `interval`, and each tick
    /// of the clock drains `part`, so the accounting is exact for every part and interval.
    held: u128,
    /// The most byte-ticks the bucket holds after a bulk charge, the capacity less the reserve, and after a suffix
    /// block, the capacity.
    bulk: u128,
    suffix: u128,
    /// The tick `held` was last drained at.
    drained: u64,
    /// When the current window opened, `None` until the first charge is offered, the bytes charged in it, and whether
    /// it refused a charge.
    opened: Option<u64>,
    used: u64,
    refused: bool,
    /// The most bytes charged in one closed window, and the windows that refused a charge.
    peak: u64,
    saturated: u64,
}

impl IoShare {
    /// The share of an owner draining `host`'s part, or `None` as [`HostShare::part`] refuses it. `largest` is the
    /// owner's largest bulk charge, which with the reserve and the slack sets the capacity.
    pub(in crate::storage) fn of(host: HostShare, largest: u64) -> Option<Self> {
        let part = host.part(largest)?;
        let capacity = (largest.saturating_add(RESERVE))
            .saturating_add(part.div_ceil(SLACK.min(host.interval)))
            .min(part);
        let ticks = u128::from(host.interval);
        Some(Self {
            part,
            interval: host.interval,
            held: 0,
            bulk: u128::from(capacity - RESERVE) * ticks,
            suffix: u128::from(capacity) * ticks,
            drained: 0,
            opened: None,
            used: 0,
            refused: false,
            peak: 0,
            saturated: 0,
        })
    }

    /// Charges `bytes` of `class` at `now` and returns whether the bucket holds them; a refusal charges nothing and
    /// marks the window saturated. A `now` before the last drain drains nothing and charges the open window.
    #[must_use]
    pub(crate) fn admit(&mut self, now: u64, bytes: u64, class: IoClass) -> bool {
        let elapsed = now.saturating_sub(self.drained);
        if elapsed > 0 {
            let drain = u128::from(elapsed) * u128::from(self.part);
            (self.held, self.drained) = (self.held.saturating_sub(drain), now);
        }
        if (self.opened).is_none_or(|opened| now.saturating_sub(opened) >= self.interval) {
            self.peak = self.peak.max(self.used);
            (self.opened, self.used, self.refused) = (Some(now), 0, false);
        }
        let room = match class {
            IoClass::Bulk => self.bulk,
            #[cfg(test)]
            IoClass::Suffix if NO_RESERVE.with(std::cell::Cell::get) => self.bulk,
            IoClass::Suffix => self.suffix,
        };
        #[cfg(test)]
        let room = if IGNORE.with(std::cell::Cell::get) {
            u128::MAX
        } else {
            room
        };
        let held = (self.held).saturating_add(u128::from(bytes) * u128::from(self.interval));
        let fits = held <= room;
        if fits {
            self.held = held;
            self.used = self.used.saturating_add(bytes);
        } else if !self.refused {
            self.refused = true;
            self.saturated += 1;
        }
        fits
    }

    /// Returns `bytes` the volume charged at this tick for a command the device then turned away, so the bucket and
    /// the window hold a metadata command's bytes only once the device accepted it.
    pub(crate) fn refund(&mut self, bytes: u64) {
        let charged = u128::from(bytes) * u128::from(self.interval);
        (self.used, self.held) = (self.used.checked_sub(bytes))
            .zip(self.held.checked_sub(charged))
            .expect("a refund returns a charge of this tick");
    }

    /// The most bytes charged in one window so far.
    pub(crate) fn peak(&self) -> u64 {
        self.peak.max(self.used)
    }

    /// The windows that refused at least one charge so far.
    pub(crate) fn saturated(&self) -> u64 {
        self.saturated
    }

    /// The part plus the bucket capacity, the most bytes one window can charge, saturating at `u64::MAX`. [`Self::of`]
    /// sets `suffix` to the `u64` capacity times the nonzero `interval`, so the quotient is that capacity exactly.
    pub(crate) fn limit(&self) -> u64 {
        let capacity = self.suffix / u128::from(self.interval);
        self.part.saturating_add(capacity as u64)
    }

    /// Whether the window open at `now` refused a charge; a window `interval` ticks old reads not full, whether or
    /// not a later charge opened the next one.
    pub(crate) fn full(&self, now: u64) -> bool {
        self.refused
            && (self.opened).is_some_and(|opened| now.saturating_sub(opened) < self.interval)
    }
}

#[cfg(test)]
thread_local! {
    /// A planted defect: every charge fits.
    pub(crate) static IGNORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect: suffix blocks take bulk room alone, with no reserve.
    pub(crate) static NO_RESERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
