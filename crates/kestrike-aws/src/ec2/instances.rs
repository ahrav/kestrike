//! `Instances` reads the zone's instances through one paged
//! `DescribeInstanceStatus` listing with `IncludeAllInstances`, so the view
//! holds instances in every state, filtered to the zone and paged by
//! `ZoneListing` under one deadline, the client's `Service::deadline` after
//! the read starts, with no retry.
//!
//! The view holds each instance in reply order with its state and its
//! system and instance status checks as the reply gives them;
//! `zone_loop::evidence::host_evidence` turns them into verdicts. An
//! instance row repeated with the same state and checks lists again in
//! reply order. An instance ID that `InstanceId` refuses, a state or check
//! outside the documented values, two differing rows for one instance of
//! any workload in the zone, and any page failure make the view `Unlisted`, never a view with instances
//! missing, so under LOST-NEEDS-TWO-CLASSES every host the directory has
//! not retired reads `Unknown`. A zone other than the listing's is
//! `Unlisted` before any request.
//!
use std::collections::BTreeMap;

use kestrike::failover::attachments::{InstanceId, Unlisted};
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::{Instance, InstanceState, StatusCheck};
use kestrike::failover::zone_loop::sources::InstanceSource;

use crate::client::Client;
use crate::clock::{Clock, SystemClock};
use crate::ec2::pages::{Describe, ZoneListing};
use crate::ec2::xml::Element;
use crate::wire::Wire;

/// `DescribeInstanceStatus` returns at most 1,000 instances a page.
const ZONE_INSTANCES: Describe = Describe {
    action: "DescribeInstanceStatus",
    set: "instanceStatusSet",
    params: &[("IncludeAllInstances", "true")],
    per_page: "1000",
};

/// The EC2 instance read of one zone for `InstanceSource::instances`,
/// complete or `Unlisted`.
///
/// The listing covers the directory's hosts when they are instances the
/// account launches itself. EC2 omits from list calls the instances an AWS
/// service manages for the account while the account hides managed
/// resources, so such an instance is outside the view.
pub struct Instances<W, C = SystemClock> {
    client: Client<W, C>,
    listing: ZoneListing,
}

impl<W: Wire, C: Clock> Instances<W, C> {
    /// `None` unless `client` signs for EC2 and `listing`'s zone name
    /// extends the client's region name in the shape of an AWS zone name.
    /// The check reads names only; it does not show that the account has
    /// the zone.
    pub fn new(client: Client<W, C>, listing: ZoneListing) -> Option<Self> {
        listing
            .served_by(&client)
            .then_some(Self { client, listing })
    }
}

impl<W: Wire, C: Clock> InstanceSource for Instances<W, C> {
    fn instances(&mut self, zone: Zone) -> Result<Vec<Instance>, Unlisted> {
        self.listing.check(zone)?;
        let deadline = self.client.deadline_from_now();
        let mut listed = Vec::new();
        let mut rows = BTreeMap::new();
        self.listing
            .read(&mut self.client, &ZONE_INSTANCES, deadline, |item| {
                let instance = instance(item).ok_or(Unlisted)?;
                match rows.insert(instance.instance, instance) {
                    Some(prior) if prior != instance => Err(Unlisted),
                    _ => {
                        listed.push(instance);
                        Ok(())
                    }
                }
            })?;
        Ok(listed)
    }
}

fn instance(item: &Element) -> Option<Instance> {
    let summary = |name: &str| item.child(name)?.text_of("status").and_then(status_check);
    Some(Instance {
        instance: InstanceId::new(item.text_of("instanceId")?)?,
        state: instance_state(item.child("instanceState")?.text_of("name")?)?,
        system_check: summary("systemStatus")?,
        instance_check: summary("instanceStatus")?,
    })
}

fn instance_state(text: &str) -> Option<InstanceState> {
    Some(match text {
        "pending" => InstanceState::Pending,
        "running" => InstanceState::Running,
        "stopping" => InstanceState::Stopping,
        "stopped" => InstanceState::Stopped,
        "shutting-down" => InstanceState::ShuttingDown,
        "terminated" => InstanceState::Terminated,
        _ => return None,
    })
}

fn status_check(text: &str) -> Option<StatusCheck> {
    Some(match text {
        "ok" => StatusCheck::Ok,
        "impaired" => StatusCheck::Impaired,
        "insufficient-data" => StatusCheck::InsufficientData,
        "initializing" => StatusCheck::Initializing,
        "not-applicable" => StatusCheck::NotApplicable,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "instances_tests.rs"]
mod tests;
