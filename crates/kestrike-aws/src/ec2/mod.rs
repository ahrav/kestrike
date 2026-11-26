//! The reconciler's EC2 reads: `Volumes` lists one volume's attachment
//! records for the `attachments::ControlPlane` seam and, built with a
//! `ZoneListing`, the zone's volumes for `VolumeSource`; `Instances` lists
//! the zone's instances for `InstanceSource`. `VolumeActions`, a separate
//! type, holds the reconciler's create, attach and detach requests.
//!
//! - One request per page, one deadline per read: a read sends each page
//!   once under the deadline the read took at its start, with no retry; a
//!   fault or an unusable reply ends it as `Unlisted`, and the caller's next
//!   tick reads again.
//! - A read returns every row its replies hold for the volumes or
//!   instances it lists, or `Unlisted`; a failed, throttled, timed-out or
//!   incomplete read is never a listing. States, statuses and checks are
//!   the replies' values, except that the zone volume read gives a volume
//!   the status listing leaves out `insufficient-data` and drops the status
//!   of a volume the volume listing leaves out. The loop decides loss from
//!   these observations, under LOSS-NEEDS-EVIDENCE for volumes and
//!   LOST-NEEDS-TWO-CLASSES for hosts.
//! - SURVEY-WRITES-NOTHING: `Volumes` and `Instances` send only
//!   `DescribeVolumes`, `DescribeVolumeStatus` and `DescribeInstanceStatus`,
//!   and expose no other request.

mod actions;
mod instances;
mod pages;
mod query;
#[cfg(test)]
pub(crate) mod replay;
mod volumes;
mod xml;

pub use actions::{LAYOUT_TAG, TOKEN_TAG, VolumeActions, VolumeSpec};
pub use instances::Instances;
pub use pages::ZoneListing;
pub use query::error_code;
pub use volumes::Volumes;
