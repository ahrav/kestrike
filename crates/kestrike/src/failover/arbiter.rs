//! The arbiter evaluates detector evidence and returns the first refusal or a flip nomination. It performs no effect
//! and spends no permit or budget. A nomination names the shard record's `(g, owner, E)` its observation was opened
//! for. The named standby's takeover compare-and-swap (`failover::takeover`) on the shard record decides whether
//! ownership changes; the standby obtains the nomination, and its detector mints no takeover witness while it
//! suspects itself. A nomination establishes no volume loss and requests no flip. Every timing input only withholds a nomination.
//!
//! Corroboration: a nomination whose local suspicion or any counted DEAD vote reads gray, an observed stall, needs
//! counted votes of two observer classes, whatever else the evidence reads. A nomination whose suspicion and counted
//! votes each read silent or declared needs the ordinary quorum alone. So a nomination whose counted votes come from
//! one observer class has a suspicion and counted readings that are each silent or declared.

use super::detect::{Liveness, ObservationGeneration, Suspicion};
use super::retire::Target;

/// Caller-supplied bounds. Durations share one suspend-aware local clock unit; quorum, rounds and hosts are counts.
/// Self-suspicion lasts at least `h`.
#[derive(Debug, Clone, Copy)]
pub struct ArbiterBounds {
    /// Detector window width; self-suspicion lasts at least one window.
    pub h: u64,
    pub holder_grace: u64,
    pub k: usize,
    pub rounds: u32,
    pub clock_age: u64,
    pub dwell: u64,
    pub hosts: usize,
}

/// Why `nominate` refused. `nominate` returns the first refusal in the order its checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decline {
    Bounds,
    /// The window is zero or self-suspicion dwell is shorter than that window.
    Dwell,
    ObserverUnhealthy,
    /// The suspicion names another host observation generation or a future stamp.
    StaleSuspicion,
    HolderGrace,
    Alive,
    Unknown,
    Quorum,
    /// Zero answers make the observer self-suspect until this local deadline.
    SelfSuspect {
        until: u64,
    },
    /// `now` precedes `holder_since`, or the self-suspicion deadline overflows.
    Time,
    ProbeBound,
    GrayNeedsSecondClass,
    /// The clock is untrusted, or its sample is after `now` or older than `clock_age`.
    ClockUntrusted,
}

impl ArbiterBounds {
    pub fn validate(self) -> Result<Self, Decline> {
        if self.h == 0 || self.dwell < self.h {
            return Err(Decline::Dwell);
        }
        if self.k < 2
            || self.k > self.hosts
            || self.rounds == 0
            || self.holder_grace == 0
            || self.clock_age == 0
        {
            return Err(Decline::Bounds);
        }
        Ok(self)
    }
}

/// A placement partition supplies one independent quorum vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition(pub u32);

/// An independent observer class supplies corroboration of a gray failure, an observed stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverClass(pub u32);

/// Votes name a partition and observer class; rounds are bounded probe rounds.
#[derive(Debug, Clone, Copy)]
pub struct Vote {
    pub partition: Partition,
    pub class: ObserverClass,
    pub round: u32,
    pub reading: Liveness,
}

/// The observer's clock trust. `sampled_at` is in the shared suspend-aware local clock unit.
#[derive(Debug, Clone, Copy)]
pub enum Clock {
    Trusted { sampled_at: u64 },
    Untrusted,
}

/// The owner host's detector observation a suspicion belongs to and the shard record's `(g, owner, E)` it was opened
/// for. A detector peer tracks one host, so the caller nominates an owner only from that owner's own peer
/// observation. A newer generation of that observation opens through `Peer::retrack` when the owner's targeted
/// `(g, owner, E)` set gains or changes a target within one boot or the owner moves to another placement partition
/// (`detect::host::Watch::sync`), and through `Peer::reboot` when the first authenticated heartbeat of a new boot
/// arrives. `nominate` compares generations only, so evidence gathered under an earlier target set or boot declines
/// `StaleSuspicion` once the caller opens the newer generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub generation: ObservationGeneration,
    pub target: Target,
}

/// The evidence for one nomination. `now`, `holder_since`, suspicion and vote stamps share one suspend-aware local
/// clock.
pub struct Nomination<'a> {
    pub now: u64,
    pub observer_healthy: bool,
    pub observation: Observation,
    pub suspicion: Suspicion,
    /// When the current holder's tenure began; the holder is not nominated within `holder_grace` of it.
    pub holder_since: u64,
    pub votes: &'a [Vote],
    pub clock: Clock,
}

/// A request to move the shard away from `target` by the named standby's takeover of the retained volume, which
/// refuses it when the shard record shows another `(g, owner, E)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlipNomination {
    pub target: Target,
}

fn age(now: u64, at: u64) -> Result<u64, Decline> {
    now.checked_sub(at).ok_or(Decline::Time)
}

/// Returns the nomination for `n.observation.target`, or the first refusal in this order: bounds, observer health,
/// stale suspicion, holder grace (or `Time` when `now` precedes `holder_since`), probe bounds, self-suspicion (or
/// `Time` when its deadline overflows), alive and unknown votes, quorum, gray corroboration and clock trust. A vote
/// counts only when it names the observation's generation and its suspicion stamp is at or before `now`. Gray
/// corroboration reads every counted vote, those after the quorum's `k`-th partition included, so one counted gray
/// vote anywhere in the list needs a second observer class.
pub fn nominate(b: &ArbiterBounds, n: &Nomination<'_>) -> Result<FlipNomination, Decline> {
    b.validate()?;
    if !n.observer_healthy {
        return Err(Decline::ObserverUnhealthy);
    }
    if n.suspicion.generation != n.observation.generation || n.suspicion.since > n.now {
        return Err(Decline::StaleSuspicion);
    }
    if age(n.now, n.holder_since)? <= b.holder_grace {
        return Err(Decline::HolderGrace);
    }
    if n.votes.len() > b.hosts {
        return Err(Decline::ProbeBound);
    }
    let in_round = |v: &Vote| v.round.wrapping_sub(1) < b.rounds;
    let counted = |v: &Vote| matches!(v.reading, Liveness::Dead(s) if s.generation == n.observation.generation && s.since <= n.now);
    let usable = |v: &Vote| in_round(v) && matches!(v.reading, Liveness::Dead(_));
    // One pass checks that every vote is in round and Dead and counts the distinct partitions of counted votes
    // up to `k`; the votes after the one that brings the count to `k` get the usability check alone. `slots` holds,
    // at index `partition % 16`, the first counted partition with that residue, tagged by bit 32 so an empty slot
    // reads 0. A counted vote whose slot holds another partition is a repeat exactly when an earlier counted vote
    // names the same partition, so the count is exact.
    let mut all_usable = true;
    let mut distinct = 0;
    let mut slots = [0u64; 16];
    let mut scan = n.votes.iter().enumerate();
    for (i, v) in scan.by_ref() {
        if !usable(v) {
            all_usable = false;
            break;
        }
        if !counted(v) {
            continue;
        }
        let p = v.partition.0;
        let slot = &mut slots[p as usize % slots.len()];
        let tagged = u64::from(p) | 1 << 32;
        let first_seen = if *slot == 0 {
            *slot = tagged;
            true
        } else {
            *slot != tagged
                && !n.votes[..i]
                    .iter()
                    .rev()
                    .any(|old| old.partition == v.partition && counted(old))
        };
        distinct += usize::from(first_seen);
        if distinct == b.k {
            break;
        }
    }
    // An empty vote list passes this gate and reaches self-suspicion.
    if !(all_usable && scan.all(|(_, v)| usable(v))) {
        if !n.votes.iter().all(in_round) {
            return Err(Decline::ProbeBound);
        }
        if n.votes.iter().any(|v| v.reading == Liveness::Alive) {
            return Err(Decline::Alive);
        }
        return Err(Decline::Unknown);
    }
    if n.votes.is_empty() {
        return Err(Decline::SelfSuspect {
            until: n.now.checked_add(b.dwell).ok_or(Decline::Time)?,
        });
    }
    if distinct < b.k {
        return Err(Decline::Quorum);
    }
    let mut first_class = None;
    let mut second_class = false;
    let mut gray = n.suspicion.failure.needs_second_class();
    #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
    let mut read = 0;
    for v in n.votes {
        #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
        if super::detect::tests::plant("stale-gray-counts") {
            gray |= matches!(v.reading, Liveness::Dead(s) if s.failure.needs_second_class());
        }
        if !counted(v) {
            continue;
        }
        #[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
        {
            read += 1;
            if read > b.k && super::detect::tests::plant("gray-unread-after-quorum") {
                break;
            }
        }
        match first_class {
            None => first_class = Some(v.class),
            Some(class) if class != v.class => {
                // A second class satisfies gray corroboration, so the votes after it need no reading.
                second_class = true;
                break;
            }
            Some(_) => {}
        }
        gray |= matches!(v.reading, Liveness::Dead(s) if s.failure.needs_second_class());
    }
    if gray && !second_class {
        return Err(Decline::GrayNeedsSecondClass);
    }
    match n.clock {
        Clock::Trusted { sampled_at } if age(n.now, sampled_at).is_ok_and(|a| a <= b.clock_age) => {
            Ok(FlipNomination {
                target: n.observation.target,
            })
        }
        _ => Err(Decline::ClockUntrusted),
    }
}
