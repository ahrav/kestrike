use std::time::Duration;

use super::{Config, DYNAMODB, EC2, MAX_DEADLINE, Service};

#[test]
fn a_valid_region_builds_the_regional_endpoint_host() {
    let config = Config::new(DYNAMODB, "us-east-1").unwrap();
    assert_eq!(config.host, "dynamodb.us-east-1.amazonaws.com");
    assert_eq!(
        Config::new(EC2, "ap-southeast-2").unwrap().host,
        "ec2.ap-southeast-2.amazonaws.com"
    );
    assert!(Config::new(DYNAMODB, &"a".repeat(32)).is_some());
}

#[test]
fn a_region_or_service_outside_the_label_alphabet_is_refused() {
    for region in [
        "",
        "US-EAST-1",
        "us-east-1.evil",
        "us/east",
        "us east",
        &"a".repeat(33),
    ] {
        assert_eq!(Config::new(DYNAMODB, region), None, "{region:?}");
    }
    for name in ["", "evil.example/?", "Dynamodb", "ec2.", "dynamodb#"] {
        let service = Service {
            name,
            deadline: Duration::from_secs(1),
            body_cap: 1,
        };
        assert_eq!(Config::new(service, "us-east-1"), None, "{name:?}");
    }
}

#[test]
fn a_deadline_past_the_bound_is_refused() {
    let at = |deadline| Service {
        deadline,
        ..DYNAMODB
    };
    assert_eq!(MAX_DEADLINE, Duration::from_secs(300));
    assert!(MAX_DEADLINE < crate::REFRESH_MARGIN);
    assert!(Config::new(at(MAX_DEADLINE), "us-east-1").is_some());
    assert_eq!(
        Config::new(at(MAX_DEADLINE + Duration::from_nanos(1)), "us-east-1"),
        None
    );
    assert_eq!(Config::new(at(Duration::MAX), "us-east-1"), None);
    assert_eq!(Config::new(at(Duration::ZERO), "us-east-1"), None);
}

#[test]
fn a_zero_body_cap_is_refused() {
    let at = |body_cap| Service {
        body_cap,
        ..DYNAMODB
    };
    assert_eq!(Config::new(at(0), "us-east-1"), None);
    assert!(Config::new(at(1), "us-east-1").is_some());
    assert!(Config::new(EC2, "us-east-1").is_some());
}

/// A DynamoDB call has 1 s and accepts a 1 MiB reply; an EC2 call has
/// 10 s and accepts a 4 MiB reply.
#[test]
fn the_shipped_services_carry_their_deadlines_and_reply_caps() {
    assert_eq!(
        DYNAMODB,
        Service {
            name: "dynamodb",
            deadline: Duration::from_secs(1),
            body_cap: 1 << 20,
        }
    );
    assert_eq!(
        EC2,
        Service {
            name: "ec2",
            deadline: Duration::from_secs(10),
            body_cap: 4 << 20,
        }
    );
}
