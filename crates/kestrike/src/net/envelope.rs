//! Supported owner configurations for one host, checked against the host's
//! declared budget.
//!
//! A host runs one owner process per volume. Each owner has its own dataplane
//! ENI, polling core, memory and shaped egress. A [`Supported`] configuration
//! names the owner count, the egress bytes per second charged to each owner,
//! and the per-owner [`OwnerDemand`]. [`check`] charges one ENI per owner,
//! multiplies each declared per-owner figure by the owner count and compares
//! every aggregate with the [`HostBudget`] limit of the same unit, EBS and
//! network limits each in their own [`Line`]. It refuses a configuration that
//! exceeds any limit and names the first limit exceeded, in [`Limit`] order.
//!
//! The arithmetic is configuration evidence. The owner, serve, client and
//! fetch reports carry the measured operating point.

use std::fmt;

use super::pace::Shaper;

/// The host's limits, each in its own unit, as the platform and deployment
/// owners declare them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostBudget {
    pub enis: u64,
    pub cores: u64,
    pub memory_bytes: u64,
    pub ebs_iops: u64,
    pub ebs_bytes_per_s: u64,
    pub network_pps: u64,
    pub network_bytes_per_s: u64,
}

/// One owner's declared demand on the host, in the budget's units. [`check`]
/// itself charges the owner's one ENI and the configuration's shaping floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerDemand {
    pub cores: u64,
    pub memory_bytes: u64,
    pub ebs_iops: u64,
    pub ebs_bytes_per_s: u64,
    pub network_pps: u64,
}

/// The host's owner count, each owner's charged egress rate in bytes per
/// second, and each owner's [`OwnerDemand`]. [`check`] charges each owner at
/// least `Shaper::FLOOR`, the lowest rate an owner's shaper settles at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supported {
    pub owners: u64,
    pub shaping_floor_bytes_per_s: u64,
    pub per_owner: OwnerDemand,
}

/// One host limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Enis,
    Cores,
    Memory,
    EbsIops,
    EbsBandwidth,
    NetworkPps,
    NetworkBandwidth,
}

impl Limit {
    fn unit(self) -> &'static str {
        match self {
            Self::Enis => "ENIs",
            Self::Cores => "cores",
            Self::Memory => "bytes",
            Self::EbsIops => "EBS IOPS",
            Self::EbsBandwidth | Self::NetworkBandwidth => "bytes/s",
            Self::NetworkPps => "packets/s",
        }
    }
}

/// `demand` uses `u128` to preserve values above `u64::MAX`, which exceed
/// every `u64` budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub limit: Limit,
    pub demand: u128,
    pub budget: u64,
}

impl Line {
    /// The budget the demand leaves unused.
    pub fn residual(&self) -> u64 {
        self.budget
            .saturating_sub(u64::try_from(self.demand).unwrap_or(u64::MAX))
    }
}

/// A configuration's arithmetic for every limit, in [`Limit`] order, built by
/// [`check`] alone. The startup report prints it on its own line after the
/// measured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arithmetic {
    owners: u64,
    lines: [Line; 7],
}

impl Arithmetic {
    pub fn owners(&self) -> u64 {
        self.owners
    }

    pub fn lines(&self) -> &[Line] {
        &self.lines
    }
}

impl fmt::Display for Arithmetic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configured: {} owners", self.owners)?;
        for line in &self.lines {
            write!(
                f,
                "; {:?} demand {} of budget {} {}, residual {}",
                line.limit,
                line.demand,
                line.budget,
                line.limit.unit(),
                line.residual()
            )?;
        }
        Ok(())
    }
}

/// A configuration over its host budget: the first limit, in [`Limit`] order,
/// the aggregate demand exceeds, with that demand and the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget(pub Line);

/// The arithmetic of `config` against `budget`.
///
/// # Errors
///
/// [`OverBudget`] naming the first limit whose aggregate demand exceeds its
/// budget.
#[must_use = "an unread check refuses nothing"]
pub fn check(config: &Supported, budget: &HostBudget) -> Result<Arithmetic, OverBudget> {
    let owners = u128::from(config.owners);
    let each = &config.per_owner;
    let line = |limit, per_owner: u64, budget| Line {
        limit,
        demand: owners * u128::from(per_owner),
        budget,
    };
    let lines = [
        line(Limit::Enis, 1, budget.enis),
        line(Limit::Cores, each.cores, budget.cores),
        line(Limit::Memory, each.memory_bytes, budget.memory_bytes),
        line(Limit::EbsIops, each.ebs_iops, budget.ebs_iops),
        line(
            Limit::EbsBandwidth,
            each.ebs_bytes_per_s,
            budget.ebs_bytes_per_s,
        ),
        line(Limit::NetworkPps, each.network_pps, budget.network_pps),
        line(
            Limit::NetworkBandwidth,
            config.shaping_floor_bytes_per_s.max(Shaper::FLOOR),
            budget.network_bytes_per_s,
        ),
    ];
    if let Some(over) = lines
        .iter()
        .find(|line| line.demand > u128::from(line.budget))
    {
        return Err(OverBudget(*over));
    }
    Ok(Arithmetic {
        owners: config.owners,
        lines,
    })
}
