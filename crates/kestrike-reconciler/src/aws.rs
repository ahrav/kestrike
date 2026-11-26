//! The service's AWS clients, each signing with the instance role's credentials read through IMDSv2
//! (`kestrike_aws::Role::instance`), the one credential source.

use kestrike_aws::ec2::{Instances, Volumes, ZoneListing};
use kestrike_aws::{Client, Config, Https, Role, SystemClock, Table};

use crate::config::Service;

/// The zone's instance listing.
pub type ZoneInstances = Instances<Https, SystemClock>;
/// The zone's volume listing.
pub type ZoneVolumes = Volumes<Https, SystemClock, ZoneListing>;

fn client(config: &Config) -> Client<Https, SystemClock> {
    Client::new(config.clone(), Https::new(), Role::instance(), SystemClock)
}

/// The zone listings of `service`'s zone over its EC2 endpoint, `None` when the zone's name does not extend the
/// region's name in the shape of an AWS zone name. Building them sends no request: a client fetches credentials at
/// its first call.
pub fn listings(service: &Service) -> Option<(ZoneInstances, ZoneVolumes)> {
    let listing = ZoneListing::new(&service.bounds, service.pages);
    let volumes = Volumes::new(client(&service.ec2))?.for_zone(listing.clone())?;
    let instances = Instances::new(client(&service.ec2), listing)?;
    Some((instances, volumes))
}

/// The store table `service` names, opened by one `DescribeTable` call.
///
/// # Errors
///
/// The text of `Table::open`'s error, naming the table.
pub fn table(service: &Service) -> Result<Table<Https, SystemClock>, String> {
    Table::open(client(&service.dynamodb), &service.table)
        .map_err(|error| format!("store table {:?}: {error}", service.table))
}
