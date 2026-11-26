//! `Volumes` reads volumes through `DescribeVolumes` and
//! `DescribeVolumeStatus`. Each read sends its requests under one deadline,
//! the client's `Service::deadline` after the read starts, with no retry.
//!
//! - `attachments` is one `DescribeVolumes` request for one volume ID. The
//!   listing preserves reply order and includes records in every attachment
//!   state. An entry is the record's `instanceId` text as the reply holds
//!   it, and the empty string when the record holds no `instanceId`,
//!   several, or one with child elements; `attachments::check` reads the
//!   empty string as foreign. A call fault, any reply but an HTTP 200 that
//!   parses as one `DescribeVolumesResponse`, a reply with a continuation
//!   token, and a `volumeSet` other than exactly the requested volume with
//!   one `attachmentSet` each give `Unlisted`.
//! - `volumes`, on a `Volumes` built with `for_zone`, lists every volume of the
//!   zone through `DescribeVolumes`, for each volume's state and attachment
//!   records, then through `DescribeVolumeStatus`, for its status, both
//!   filtered to the zone and paged by `ZoneListing`. The zone filter
//!   selects the account's volumes of every workload, so the page bound
//!   covers all of them. The loop judges the volumes its records name. On an
//!   observation call that can reach a loss decision it also reads the store
//!   record of each other listed volume that reads impaired, lost or
//!   unvalued, one read per such volume and call (OBSERVE-ORDER in
//!   `zone_loop::observe`); this adapter issues none of those reads.
//!   The view holds the volumes in `DescribeVolumes` order, with the states,
//!   statuses and attachment entries as the replies give them. A volume the
//!   status listing leaves out reads `insufficient-data`, which the loop's
//!   volume memory treats as no value, and the status of a volume the volume
//!   listing leaves out is dropped. A volume row repeated with the same
//!   state and the same attachment entries, in any order, lists again in
//!   reply order, and a status repeated with the same value counts once. A
//!   volume ID that `VolumeId` refuses, a state or status outside the
//!   documented values, and two differing rows or two differing statuses
//!   for one volume make the view `Unlisted`, as does any page failure. A
//!   zone other than the listing's is `Unlisted` before any request.

use std::collections::BTreeMap;

use kestrike::failover::attachments::{ControlPlane, Unlisted};
use kestrike::failover::records::VolumeId;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::evidence::{ListedVolumeState, VolumeCondition, VolumeStatus};
use kestrike::failover::zone_loop::sources::{ListedVolume, VolumeSource};

use crate::client::Client;
use crate::clock::{Clock, SystemClock};
use crate::ec2::pages::{Describe, ZoneListing};
use crate::ec2::query::{self, next_token};
use crate::ec2::xml::Element;
use crate::wire::Wire;

const DESCRIBE_VOLUMES: &str = "DescribeVolumes";

/// A zone read asks `DescribeVolumes` for at most 100 volumes a page, a
/// fifth of the API's 500. A volume record carries up to 50 tags, and a
/// page of 100 volumes with 50 tags each, 128-character keys and
/// 256-character values, is about 2.2 MB when each tag character takes
/// one byte of the reply, inside `EC2.body_cap` of 4 MiB. The cap counts
/// the reply's bytes. A multibyte character takes up to four bytes, and
/// `&` takes five as `&amp;`. Tag text of such characters can make a
/// full page pass the cap, and that read is `Unlisted`.
const ZONE_VOLUMES: Describe = Describe {
    action: DESCRIBE_VOLUMES,
    set: "volumeSet",
    params: &[],
    per_page: "100",
};

/// `DescribeVolumeStatus` returns at most 1,000 statuses a page.
const ZONE_STATUSES: Describe = Describe {
    action: "DescribeVolumeStatus",
    set: "volumeStatusSet",
    params: &[],
    per_page: "1000",
};

/// The EC2 volume reads: `ControlPlane::attachments` for one volume, and
/// `VolumeSource::volumes` for the zone of a `ZoneListing`, each complete
/// or `Unlisted`.
///
/// The zone listing covers the cache volumes when they are volumes the
/// account creates itself. EC2 omits from list calls the volumes an AWS
/// service manages for the account while the account hides managed
/// resources, so such a volume is outside the view.
///
/// `Z` is `()` for the one-volume attachment listing alone, and
/// `ZoneListing` for an adapter that also implements `VolumeSource`.
pub struct Volumes<W, C = SystemClock, Z = ()> {
    client: Client<W, C>,
    listing: Z,
}

impl<W: Wire, C: Clock> Volumes<W, C> {
    /// `None` unless `client` signs for the EC2 service.
    pub fn new(client: Client<W, C>) -> Option<Self> {
        client.is_ec2().then_some(Self {
            client,
            listing: (),
        })
    }

    /// The adapter that also lists `listing`'s zone, `None` unless the
    /// zone's name extends the client's region name in the shape of an AWS
    /// zone name. The check reads names only; it does not show that the
    /// account has the zone.
    pub fn for_zone(self, listing: ZoneListing) -> Option<Volumes<W, C, ZoneListing>> {
        listing.served_by(&self.client).then(|| Volumes {
            client: self.client,
            listing,
        })
    }
}

impl<W: Wire, C: Clock, Z> ControlPlane for Volumes<W, C, Z> {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        let params = [("VolumeId.1", volume.as_str())];
        let deadline = self.client.deadline_from_now();
        let document = query::exchange(&mut self.client, DESCRIBE_VOLUMES, &params, deadline)?;
        if next_token(&document)?.is_some() {
            return Err(Unlisted);
        }
        let [listed] = document.items("volumeSet").ok_or(Unlisted)? else {
            return Err(Unlisted);
        };
        if listed.text_of("volumeId") != Some(volume.as_str()) {
            return Err(Unlisted);
        }
        attachment_entries(listed)
    }
}

impl<W: Wire, C: Clock> VolumeSource for Volumes<W, C, ZoneListing> {
    fn volumes(&mut self, zone: Zone) -> Result<Vec<ListedVolume>, Unlisted> {
        self.listing.check(zone)?;
        let deadline = self.client.deadline_from_now();
        let mut listed: Vec<(VolumeId, Row)> = Vec::new();
        let mut rows = BTreeMap::new();
        self.listing
            .read(&mut self.client, &ZONE_VOLUMES, deadline, |item| {
                let volume = volume_id(item)?;
                let state = item.text_of("status").and_then(volume_state);
                let row = (state.ok_or(Unlisted)?, attachment_entries(item)?);
                match rows.insert(volume, listed.len()) {
                    Some(prior) if !same_row(&listed[prior].1, &row) => Err(Unlisted),
                    _ => {
                        listed.push((volume, row));
                        Ok(())
                    }
                }
            })?;
        let mut statuses = BTreeMap::new();
        self.listing
            .read(&mut self.client, &ZONE_STATUSES, deadline, |item| {
                let volume = volume_id(item)?;
                let reported = item
                    .child("volumeStatus")
                    .and_then(|info| info.text_of("status"));
                let status = reported.and_then(volume_status).ok_or(Unlisted)?;
                match statuses.insert(volume, status) {
                    Some(prior) if prior != status => Err(Unlisted),
                    _ => Ok(()),
                }
            })?;
        Ok(listed
            .into_iter()
            .map(|(volume, (state, attachments))| {
                let status = statuses.get(&volume).copied();
                ListedVolume {
                    volume,
                    condition: VolumeCondition {
                        state,
                        status: status.unwrap_or(VolumeStatus::InsufficientData),
                    },
                    attachments,
                }
            })
            .collect())
    }
}

/// A volume's state and attachment entries, as one row of a zone listing.
type Row = (ListedVolumeState, Vec<String>);

/// Whether two rows of one volume agree: the same state, and the same
/// attachment entries counted with repeats, in any order.
fn same_row(first: &Row, second: &Row) -> bool {
    first.0 == second.0 && sorted(&first.1) == sorted(&second.1)
}

fn sorted(entries: &[String]) -> Vec<&String> {
    let mut entries: Vec<&String> = entries.iter().collect();
    entries.sort_unstable();
    entries
}

fn attachment_entries(volume: &Element) -> Result<Vec<String>, Unlisted> {
    let records = volume.items("attachmentSet").ok_or(Unlisted)?;
    Ok(records
        .iter()
        .map(|record| record.text_of("instanceId").unwrap_or_default().to_owned())
        .collect())
}

fn volume_id(item: &Element) -> Result<VolumeId, Unlisted> {
    item.text_of("volumeId")
        .and_then(VolumeId::new)
        .ok_or(Unlisted)
}

fn volume_state(text: &str) -> Option<ListedVolumeState> {
    Some(match text {
        "creating" => ListedVolumeState::Creating,
        "available" => ListedVolumeState::Available,
        "in-use" => ListedVolumeState::InUse,
        "deleting" => ListedVolumeState::Deleting,
        "deleted" => ListedVolumeState::Deleted,
        "error" => ListedVolumeState::Error,
        _ => return None,
    })
}

fn volume_status(text: &str) -> Option<VolumeStatus> {
    Some(match text {
        "ok" => VolumeStatus::Ok,
        "warning" => VolumeStatus::Warning,
        "impaired" => VolumeStatus::Impaired,
        "insufficient-data" => VolumeStatus::InsufficientData,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "volumes_tests.rs"]
mod tests;
