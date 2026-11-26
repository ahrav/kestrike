//! The supported-configuration check against a host budget: the arithmetic of a configuration inside every
//! limit, and a planted over-budget configuration for each limit refused naming that limit.

use super::envelope::{HostBudget, Limit, Line, OverBudget, OwnerDemand, Supported, check};
use super::pace::Shaper;

const BUDGET: HostBudget = HostBudget {
    enis: 8,
    cores: 32,
    memory_bytes: 256 << 30,
    ebs_iops: 160_000,
    ebs_bytes_per_s: 10 << 30,
    network_pps: 8_000_000,
    network_bytes_per_s: 25 << 30,
};

const PER_OWNER: OwnerDemand = OwnerDemand {
    cores: 2,
    memory_bytes: 16 << 30,
    ebs_iops: 20_000,
    ebs_bytes_per_s: 1 << 30,
    network_pps: 500_000,
};

fn config(owners: u64) -> Supported {
    Supported {
        owners,
        shaping_floor_bytes_per_s: 2 << 30,
        per_owner: PER_OWNER,
    }
}

/// For a configuration inside every limit, [`check`] returns each limit's aggregate demand, budget and
/// residual in the budget's units, one [`Line`] per limit in [`Limit`] declaration order. The printed
/// arithmetic starts with the owner count.
#[test]
fn a_configuration_inside_every_limit_reports_its_arithmetic() {
    let arithmetic = check(&config(8), &BUDGET).unwrap();
    let limits: Vec<_> = arithmetic.lines().iter().map(|line| line.limit).collect();
    assert_eq!(
        limits,
        [
            Limit::Enis,
            Limit::Cores,
            Limit::Memory,
            Limit::EbsIops,
            Limit::EbsBandwidth,
            Limit::NetworkPps,
            Limit::NetworkBandwidth,
        ]
    );
    let demand = |limit| {
        arithmetic
            .lines()
            .iter()
            .find(|line| line.limit == limit)
            .unwrap()
            .demand
    };
    assert_eq!(arithmetic.owners(), 8);
    assert_eq!(demand(Limit::Enis), 8);
    assert_eq!(demand(Limit::Cores), 16);
    assert_eq!(demand(Limit::Memory), 128 << 30);
    assert_eq!(demand(Limit::EbsIops), 160_000);
    assert_eq!(demand(Limit::EbsBandwidth), 8 << 30);
    assert_eq!(demand(Limit::NetworkPps), 4_000_000);
    assert_eq!(demand(Limit::NetworkBandwidth), 16 << 30);
    assert_eq!(
        arithmetic.lines()[0].residual(),
        0,
        "the ENIs are spent exactly"
    );
    let printed = arithmetic.to_string();
    assert!(
        printed.starts_with("configured: 8 owners; Enis demand 8 of budget 8 ENIs, residual 0"),
        "{printed}"
    );
    assert!(
        printed.contains("EbsIops demand 160000 of budget 160000 EBS IOPS"),
        "{printed}"
    );
    assert!(
        printed.contains(
            "NetworkBandwidth demand 17179869184 of budget 26843545600 bytes/s, residual 9663676416"
        ),
        "{printed}"
    );
}

/// A planted over-budget configuration for each limit, one owner past the ENIs, a core demand, a bandwidth
/// floor and an IOPS demand past their budgets among them, is refused naming that limit with its demand and
/// budget; EBS and network bandwidth fail apart.
#[test]
fn each_over_budget_configuration_is_refused_naming_its_binding_limit() {
    let cases: [(Supported, Limit, u128); 7] = [
        (config(9), Limit::Enis, 9),
        (
            Supported {
                per_owner: OwnerDemand {
                    cores: 5,
                    ..PER_OWNER
                },
                ..config(8)
            },
            Limit::Cores,
            40,
        ),
        (
            Supported {
                per_owner: OwnerDemand {
                    memory_bytes: 33 << 30,
                    ..PER_OWNER
                },
                ..config(8)
            },
            Limit::Memory,
            264 << 30,
        ),
        (
            Supported {
                per_owner: OwnerDemand {
                    ebs_iops: 20_001,
                    ..PER_OWNER
                },
                ..config(8)
            },
            Limit::EbsIops,
            160_008,
        ),
        (
            Supported {
                per_owner: OwnerDemand {
                    ebs_bytes_per_s: 2 << 30,
                    ..PER_OWNER
                },
                ..config(8)
            },
            Limit::EbsBandwidth,
            16 << 30,
        ),
        (
            Supported {
                per_owner: OwnerDemand {
                    network_pps: 1_000_001,
                    ..PER_OWNER
                },
                ..config(8)
            },
            Limit::NetworkPps,
            8_000_008,
        ),
        (
            Supported {
                shaping_floor_bytes_per_s: 4 << 30,
                ..config(8)
            },
            Limit::NetworkBandwidth,
            32 << 30,
        ),
    ];
    for (over, limit, demand) in cases {
        let Err(OverBudget(line)) = check(&over, &BUDGET) else {
            panic!("{limit:?}: an over-budget configuration is refused");
        };
        assert_eq!((line.limit, line.demand), (limit, demand), "{limit:?}");
        assert!(line.demand > u128::from(line.budget), "{limit:?}");
    }
    let most_owners = Supported {
        owners: u64::MAX,
        ..config(1)
    };
    assert_eq!(
        check(&most_owners, &BUDGET),
        Err(OverBudget(Line {
            limit: Limit::Enis,
            demand: u128::from(u64::MAX),
            budget: 8
        })),
        "u64::MAX owners demand u64::MAX ENIs"
    );
}

/// Each owner's shaper admits at least [`Shaper::FLOOR`], so a smaller declared floor is charged at
/// [`Shaper::FLOOR`]: eight owners declared at one byte per second exceed a budget of three shaper floors.
#[test]
fn a_declared_floor_below_the_shapers_is_charged_at_the_shapers_floor() {
    let below_shaper_floor = Supported {
        shaping_floor_bytes_per_s: 1,
        ..config(8)
    };
    let narrow = HostBudget {
        network_bytes_per_s: 3 * Shaper::FLOOR,
        ..BUDGET
    };
    let Err(OverBudget(line)) = check(&below_shaper_floor, &narrow) else {
        panic!("a declared floor below the shaper's is charged at the shaper's floor");
    };
    assert_eq!(
        (line.limit, line.demand),
        (Limit::NetworkBandwidth, u128::from(8 * Shaper::FLOOR))
    );
}

/// An aggregate past `u64::MAX` exceeds even a `u64::MAX` budget: two owners of 2^63 bytes each demand
/// 2^64 bytes.
#[test]
fn an_aggregate_past_u64_max_exceeds_a_u64_max_budget() {
    let overflowing = Supported {
        per_owner: OwnerDemand {
            memory_bytes: 1 << 63,
            ..PER_OWNER
        },
        ..config(2)
    };
    let unbounded_memory = HostBudget {
        memory_bytes: u64::MAX,
        ..BUDGET
    };
    let Err(OverBudget(line)) = check(&overflowing, &unbounded_memory) else {
        panic!("an aggregate past u64::MAX exceeds a u64::MAX budget");
    };
    assert_eq!(
        (line.limit, line.demand, line.residual()),
        (Limit::Memory, 1 << 64, 0)
    );
}

/// Every declared configuration is checked against the budget on its own, and a configuration over two
/// limits names the first in limit order.
#[test]
fn every_declared_configuration_is_checked_on_its_own() {
    let results: Vec<_> = [config(4), config(9), config(8)]
        .iter()
        .map(|config| check(config, &BUDGET))
        .collect();
    assert_eq!(results[0].map(|arithmetic| arithmetic.owners()), Ok(4));
    assert!(
        matches!(
            results[1],
            Err(OverBudget(Line {
                limit: Limit::Enis,
                ..
            }))
        ),
        "nine owners exceed the ENIs and the EBS IOPS, and the ENIs come first"
    );
    assert_eq!(results[2].map(|arithmetic| arithmetic.owners()), Ok(8));
}
