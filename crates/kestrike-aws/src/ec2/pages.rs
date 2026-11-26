//! A zone read lists every page of one describe action filtered to one
//! availability zone, or gives `Unlisted`.
//!
//! - Each page is one `exchange` request under the read's one deadline:
//!   each page's wire wait ends by that deadline plus the wire's slack, and
//!   a later page gets the time earlier pages, and the decoding of their
//!   replies, left. Decoding the last reply and joining the pages run after
//!   the last wire wait.
//! - The read follows each page's continuation token, at most
//!   `ZoneListing`'s page bound pages per describe action. A token past the
//!   bound and a token the read already followed give `Unlisted`, so no page
//!   is sent twice.
//! - A failure of any page makes the whole read `Unlisted`: the caller keeps
//!   the items it was handed only when every page arrived. A page may hold
//!   no item and still carry a token.

use std::num::NonZeroU16;
use std::time::Instant;

use kestrike::failover::attachments::Unlisted;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::config::ZoneBounds;

use crate::client::Client;
use crate::clock::Clock;
use crate::ec2::query::{self, next_token};
use crate::ec2::xml::Element;
use crate::wire::Wire;

/// Whether `suffix`, the part of a zone name after its region name, has the
/// shape of an AWS zone: one lowercase letter for a standard zone, or `-`
/// and labels of lowercase letters and digits joined by single hyphens,
/// whose last label ends in a lowercase letter for a local zone, as in
/// `-bos-1a`, or whose last two labels are `wlz` and digits for a
/// wavelength zone, as in `-wl1-bos-wlz-1`. A local or wavelength network
/// border group name, such as `-bos-1` or `-wl1`, fails it.
fn zone_suffix(suffix: &str) -> bool {
    let Some(labels) = suffix.strip_prefix('-') else {
        return suffix.len() == 1 && suffix.bytes().all(|byte| byte.is_ascii_lowercase());
    };
    let labels: Vec<&str> = labels.split('-').collect();
    let readable = labels.iter().all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    });
    let local = labels
        .last()
        .is_some_and(|last| last.ends_with(|c: char| c.is_ascii_lowercase()));
    let wavelength = matches!(labels.as_slice(), [.., "wlz", last] if last.bytes().all(|byte| byte.is_ascii_digit()));
    readable && (local || wavelength)
}

/// Whether `client` signs for EC2 in a region whose name the zone name
/// `name` extends in the shape of an AWS zone name, as
/// `ZoneListing::served_by` states.
pub(crate) fn serves<W: Wire, C: Clock>(client: &Client<W, C>, name: &str) -> bool {
    let region = client.region();
    client.is_ec2()
        && region.ends_with(|c: char| c.is_ascii_digit())
        && name.strip_prefix(region).is_some_and(zone_suffix)
}

/// One describe action of a zone read: its name, the set its replies hold
/// the items in, its parameters beside the zone filter, and the most items
/// it returns a page.
pub(crate) struct Describe {
    pub(crate) action: &'static str,
    pub(crate) set: &'static str,
    pub(crate) params: &'static [(&'static str, &'static str)],
    pub(crate) per_page: &'static str,
}

/// The zone a listing adapter reads, its availability-zone name, and its
/// page bound per describe action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneListing {
    zone: Zone,
    name: String,
    pages: NonZeroU16,
}

impl ZoneListing {
    /// The listing of the zone `bounds` configures, filtered by its validated
    /// availability-zone name, with at most `pages` pages for each describe
    /// action of a read.
    ///
    /// A describe action that needs more than `pages` pages reads
    /// `Unlisted`, so `pages` must cover every volume and every instance the
    /// account holds in the zone, of every workload. The adapters ask for at
    /// most 100 volumes a page of `DescribeVolumes`, 1,000 statuses a page
    /// of `DescribeVolumeStatus` and 1,000 instances a page of
    /// `DescribeInstanceStatus`, so the volume listing sets the bound, and
    /// the zone's volume count divided by 100 is a lower bound on `pages`:
    /// EC2 may return fewer items a page than it is asked for. Every page of
    /// a read also shares the client's one `Service::deadline`, which bounds
    /// the pages a read fetches in time, and each page must fit the client's
    /// `Service::body_cap`; the volume page size is sized for
    /// `config::EC2`'s cap.
    ///
    /// The caller must give the loop and its adapters `ZoneBounds` from one
    /// validated configuration, whose name is the exact EC2 zone name of
    /// the zone where the directory's hosts and volumes run, in the account
    /// the clients sign as. An adapter compares only the zone number with
    /// the zone a read names and filters by this name, so a listing under
    /// another zone's name reads as a complete listing of that zone, empty
    /// for a name the account lacks.
    pub fn new(bounds: &ZoneBounds, pages: NonZeroU16) -> Self {
        Self {
            zone: bounds.config().zone,
            name: bounds.config().name.clone(),
            pages,
        }
    }

    /// Whether `client` signs for EC2 in a region whose name the zone's name
    /// extends in the shape of an AWS zone name; `zone_suffix` states the
    /// shape. An AWS region name ends in a digit. The check reads the two
    /// names only; a name of that shape that the account lacks still passes
    /// it. A client of another region would answer the zone filter with an
    /// empty listing.
    pub(crate) fn served_by<W: Wire, C: Clock>(&self, client: &Client<W, C>) -> bool {
        serves(client, &self.name)
    }

    /// `Unlisted` for any zone but the configured one, before any request.
    pub(crate) fn check(&self, zone: Zone) -> Result<(), Unlisted> {
        (zone == self.zone).then_some(()).ok_or(Unlisted)
    }

    /// Sends the pages of `describe` and hands each item of each page's set
    /// to `each`, in reply order.
    pub(crate) fn read<W: Wire, C: Clock>(
        &self,
        client: &mut Client<W, C>,
        describe: &Describe,
        deadline: Instant,
        mut each: impl FnMut(&Element) -> Result<(), Unlisted>,
    ) -> Result<(), Unlisted> {
        let mut followed: Vec<String> = Vec::new();
        loop {
            let mut params = vec![
                ("Filter.1.Name", "availability-zone"),
                ("Filter.1.Value.1", self.name.as_str()),
            ];
            params.extend_from_slice(describe.params);
            params.push(("MaxResults", describe.per_page));
            if let Some(token) = followed.last() {
                params.push(("NextToken", token));
            }
            let page = query::exchange(client, describe.action, &params, deadline)?;
            for item in page.items(describe.set).ok_or(Unlisted)? {
                each(item)?;
            }
            let Some(token) = next_token(&page)? else {
                return Ok(());
            };
            let sent = followed.len() + 1;
            if sent >= usize::from(self.pages.get()) || followed.iter().any(|seen| seen == token) {
                return Err(Unlisted);
            }
            followed.push(token.to_owned());
        }
    }
}
