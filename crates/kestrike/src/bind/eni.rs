//! Identity of the dataplane ENI, resolved from instance metadata to one
//! PCI function on the `ena` driver, its kernel network state, and the
//! next-hop MAC toward each peer, all read while the ENI is still on `ena`.
//!
//! The configured ENI ID must name exactly one interface in the metadata,
//! which is not the primary one (device and network-card index zero), and
//! whose permanent MAC names exactly one network device, a function of an
//! ENA PCI ID the pinned driver supports, that carries no default route of
//! the main IPv4 table, no IPv6 default route and no global IPv6 address,
//! since release restores IPv4 state. Each peer in the ENI's subnet is reached directly;
//! any other is reached through the subnet's router, the subnet's first host
//! address.
//!
//! A bind admits the device's network state only inside the restoration
//! domain release replays: the MTU, the administrative link state, IPv4
//! addresses with their local address and prefix, broadcast, `metric` and
//! `noprefixroute`, each a local address of `scope global` labeled with the
//! device's name outside 127.0.0.0/8, and main-table IPv4 routes with one
//! next hop whose every listed word release replays as the same route (see
//! `RouteWords::read`), each with a listed scope unless it is a unicast
//! route through a gateway, and each gateway reached by an address or a
//! route release replays first (see `Reach`), an
//! IPv6 gateway only at an MTU of at least 1280 and on a host whose
//! `net.ipv6.conf.default.disable_ipv6` reads 0, since the kernel takes an
//! IPv6 next hop only on a device with IPv6 enabled and the returned device
//! starts from that default: no two under one destination, type of service
//! and metric, and none that shares those three with a host route, a
//! main-table route of another device or of a device-less type
//! (`blackhole`, `unreachable`, `prohibit`, `throw`, `nat`, `xresolve`).
//! The capture reads the host's complete route listing beside the listing
//! by device, because `ip` before 6.10 leaves out of a listing by device
//! each route that names its device only in a next hop or a nexthop object,
//! or names none. A host route stays when the device leaves `ena`, and the
//! capture passes over it. It refuses with `"routes"` for a route the bind
//! would remove: a main-table route of any device whose `src` is one of the
//! device's addresses, a multipath route with a next hop on the device, a
//! device-less route through a nexthop object unless the listing names
//! another device for it, and any other route that names no device, which
//! is every route through a nexthop object on a host with
//! `net.ipv4.nexthop_compat_mode` set to 0. It also refuses with `"routes"`
//! for a device-less route of the main or local table, or of a table a
//! policy rule reads before the main table, that the kernel's lookup of a
//! recorded gateway returns, for a policy rule that ends that lookup before
//! the main table, and for a rule listing in which no rule reads the main
//! table for that gateway (see `Reach`). An address or route line with
//! whitespace outside ASCII refuses, since `ip` reads that whitespace as
//! part of a word. The capture drops what the kernel derives: the `secondary` and `dynamic`
//! flags, the `valid_lft` and `preferred_lft` lifetimes, which replay renews
//! to forever, the `linkdown` and `dead` route flags, the local table's
//! `proto kernel` entries of the device's local and broadcast addresses, and
//! the kernel's IPv6 entries of its one link-local address: `fe80::/64`, its
//! `local` entry and `multicast ff00::/8`. It refuses every other address
//! word, including another scope, any label other than the device's name,
//! `peer` and `deprecated`, any other route of the device in either family,
//! an IPv4 rule naming the device by its name or an altname, or one of its
//! IPv4 addresses, an IPv6 rule naming the device by its name or an altname,
//! or its link-local address, and any IPv6 address beyond one link-local
//! address. A host forwarding IPv6 holds the kernel's `anycast fe80::` entry
//! in the local table, which refuses with `"routes"`. On a host with IPv6
//! disabled, the capture reads the link line alone for the altnames. A
//! route through a nexthop object, `nhid N`, refuses in either family, since
//! `route replace` needs the object and the kernel removes it with the
//! device. The capture supports Linux 5.14 and later: an earlier kernel
//! also derives a `broadcast` entry for a prefix's network address, which
//! refuses with `"routes"`.
//!
//! Release replays `NetState` alone: the MTU, the link state, each recorded
//! address through `addr replace` and each recorded main-table route
//! through `route replace`, host-scope routes first, then link-scope routes
//! and every other route with no gateway, then the rest, so each gateway's
//! route precedes the routes through it. The kernel derives the returned device's other
//! entries from those addresses and the host's IPv6 settings at release:
//! the prefix route of the first address of each network and prefix length
//! unless that address holds `noprefixroute` or the network lies in
//! 0.0.0.0/8, the local table's entries, and the IPv6 link-local address
//! with its routes. The
//! capture admits each derived entry by its printed shape and admits a
//! device that holds any subset of them. A link-local address assigned by
//! hand, or a derived entry deleted before the bind, is replaced by the
//! kernel's own on the returned device.
//!
//! A device with a master refuses with `"master"`. A device that another
//! device of its network namespace is stacked on, which sysfs links from the
//! device's directory as `upper_<name>`, refuses with `"upper"`: the kernel
//! removes a VLAN, a macvlan, a MACsec device and a VXLAN device with the
//! device beneath it, with their addresses and routes, and release replays
//! the state of the ENI's device alone. Sysfs holds an `upper_<name>` link
//! only between two devices of one network namespace. The capture therefore
//! admits a device whose upper device resides in another network namespace,
//! such as a macvlan moved into a container, and the kernel removes that
//! upper device with the ENI's device. The bind removes the
//! device with the rest of its state: the link's `alias`, `group` and
//! `qlen`, its altnames, nexthop objects that name the device, neighbor
//! entries, queueing disciplines and device sysctls. The capture admits
//! the device whatever that state is, and the returned device starts from
//! the kernel's defaults for it. A nexthop group that spans devices keeps
//! its other members and loses the one on this device.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::host::{Host, Kernel, Started, SysfsKernel, batch};
use super::metadata::Metadata;

/// The ENA PCI vendor and device IDs the pinned driver probes.
pub(crate) const ENA_PCI: [(u16, u16); 2] = [(0x1d0f, 0xec20), (0x1d0f, 0xec21)];
pub(crate) const ENA_DRIVER: &str = "ena";
/// `ip IP_SHOW` prints, one per line, the show commands' output on its
/// standard input: the device's IPv4 addresses, its IPv4 routes in every
/// table, its link line, every IPv4 route of the host and the host's IPv4
/// rules.
pub(crate) const IP_SHOW: [&str; 4] = ["-4", "-o", "-batch", "-"];
/// `ip IP_SHOW6` prints, one per line, on a host with IPv6, the device's
/// IPv6 routes in every table, the host's IPv6 rules, the device's link
/// line with its altnames and every IPv6 route of the host. On a host
/// without IPv6 it prints the link line alone. The device's IPv6 addresses
/// come from the kernel's `if_inet6` table.
const IP_SHOW6: [&str; 4] = ["-6", "-o", "-batch", "-"];
const IFF_UP: u32 = 1;
/// Listings of one table [`settled_table`] takes before it refuses.
const TABLE_LISTINGS: usize = 6;
/// Passes over a device's sysfs entries and route tables [`Host::ena_function`] takes before it refuses.
const NAME_PASSES: u32 = 8;

/// The seven counts of `proc/net/rt6_stats`, the IPv6 tables' nodes and routes among them. A route's deletion moves
/// `fib_rt_entries` and `fib_discarded_routes`, which never falls, and a change to the tables' shape moves
/// `fib_nodes`.
///
/// # Errors
///
/// The error of a failed read, or `InvalidData` for a file other than seven hexadecimal counts.
fn route_census(net: &Path) -> io::Result<[u32; 7]> {
    let text = fs::read_to_string(net.join("rt6_stats"))?;
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "rt6_stats");
    let fields: Vec<&str> = text.split_whitespace().collect();
    let mut counts = [0; 7];
    if fields.len() != counts.len() {
        return Err(malformed());
    }
    for (count, field) in counts.iter_mut().zip(fields) {
        *count = u32::from_str_radix(field, 16).map_err(|_| malformed())?;
    }
    Ok(counts)
}

/// The text of `table`, `ipv6_route` or `if_inet6` under `proc/net`, from two listings that agree, each between two
/// equal reads of [`route_census`]. The kernel resumes either listing at each `read` call by a count of the records
/// it has returned, over the whole route table or within one bucket of the address table, so a record deleted
/// between two calls keeps a later record, present throughout, out of the listing, in the route table at any size
/// above one call's page and in the address table wherever a call ends, and one added lists a record twice. An
/// address that leaves or arrives takes its local route with it, which moves the census. The kernel updates its
/// counts apart from the tables its listings walk, so a listing under a still census can still have lost a record;
/// two such listings that lost the same record would each have raced a change, and the answer takes at most
/// `TABLE_LISTINGS` listings, else refuses.
///
/// # Errors
///
/// The error of opening the table, `NotFound` for a host without IPv6 included. Otherwise an error of another kind
/// when a read fails, `rt6_stats` is missing or malformed, or no two listings under a still census agreed.
fn settled_table(net: &Path, table: &str) -> io::Result<String> {
    // Once the table opens, a missing census is a failure to verify, not a host without IPv6.
    let census = || route_census(net).map_err(|error| io::Error::other(error.to_string()));
    let mut still: Option<String> = None;
    for _ in 0..TABLE_LISTINGS {
        // The kernel starts the listing at the first `read`, so the open may precede the census.
        let mut listing = fs::File::open(net.join(table))?;
        let before = census()?;
        let mut text = String::new();
        listing.read_to_string(&mut text)?;
        if census()? != before {
            continue;
        }
        if still.as_ref() == Some(&text) {
            return Ok(text);
        }
        still = Some(text);
    }
    Err(io::Error::other(
        "no two listings of the table under a still census agreed",
    ))
}

/// The `if_inet6` scope bits of host, link and site addresses. An address
/// with all three bits clear has global scope.
const IPV6_LOCAL_SCOPES: u32 = 0x10 | 0x20 | 0x40;
/// The `if_inet6` scope of a link-local address.
const IPV6_LINK_SCOPE: u32 = 0x20;
/// Rounds of solicitations an unresolved next hop gets before `next_hops`
/// refuses it.
const SOLICITS: u32 = 5;
/// The most interfaces a metadata listing may name.
pub(crate) const LISTING_LIMIT: usize = 128;
const REQUESTS_AT_ONCE: usize = 1 + 32 + 5;
/// The time an ENI resolution may take on the kernel's monotonic clock: a
/// round of metadata requests that ends past it refuses the resolution, so
/// a refused resolution has run at most this long plus one round, `during`
/// included.
pub(crate) const DISCOVERY_LIMIT: Duration = Duration::from_secs(15);
/// When each round reads the neighbor table again, by time since its
/// solicitations went out. A round that leaves a hop unresolved ends at the
/// last offset. A hop that answers before the first offset resolves at
/// that read.
/// A hop that never answers is refused after at least 5 s.
const READS: [Duration; 4] = [
    Duration::from_millis(1),
    Duration::from_millis(10),
    Duration::from_millis(100),
    Duration::from_millis(1000),
];

/// The `ip IP_SHOW` and `ip IP_SHOW6` programs a network read feeds and
/// finishes.
pub(crate) struct IpShows<'k> {
    ip: Box<dyn Started + 'k>,
    ip6: Box<dyn Started + 'k>,
}

impl<'k> IpShows<'k> {
    pub(crate) fn start(kernel: &'k dyn Kernel) -> io::Result<Self> {
        Ok(Self {
            ip: kernel.start("ip", &IP_SHOW)?,
            ip6: kernel.start("ip", &IP_SHOW6)?,
        })
    }
}

/// The interfaces the metadata listed and the MAC the ENI ID matched in one
/// resolution. A later resolution of the same ENI requests the listing, the
/// ID of each listed interface and the matched interface's fields at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sighting {
    listed: Vec<[u8; 6]>,
    mac: [u8; 6],
}

#[cfg(test)]
impl Sighting {
    /// A sighting of `listed` interfaces that matched `mac`.
    pub(crate) fn new(listed: Vec<[u8; 6]>, mac: [u8; 6]) -> Self {
        Self { listed, mac }
    }
}

/// The resolved dataplane ENI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eni {
    pub id: String,
    pub mac: [u8; 6],
    pub ipv4: Ipv4Addr,
    pub subnet: String,
    /// The subnet's network address and prefix length.
    pub cidr: (Ipv4Addr, u8),
    pub device_number: u32,
    pub network_card: u32,
    /// The kernel's network device for the ENI, and its PCI address.
    pub netdev: String,
    pub bdf: String,
}

/// The kernel network state of the ENI's device, which release restores:
/// its MTU, its administrative link state, its IPv4 addresses and its
/// main-table IPv4 routes. The capture admits only the module's restoration
/// domain. A bind compares two captures with `same_configuration`, which
/// ignores the order of addresses and routes. Release replays a record as it
/// stands, whatever the admission rule a later binder applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetState {
    /// The device's MTU, as the kernel reports it.
    pub mtu: NonZeroU32,
    pub up: bool,
    /// IPv4 addresses with their prefix, their `brd` broadcast address when
    /// they have one, and the `metric` and `noprefixroute` that shape their
    /// prefix route, `10.0.1.5/24 brd 10.0.1.255 metric 1003`. Replay assigns
    /// each address with a forever lifetime.
    pub addresses: Vec<String>,
    /// Main-table IPv4 routes through the device, as `ip route` prints them
    /// without the device and without state flags the kernel derives, in
    /// listed order. Release replays them by scope: host, then link, then
    /// the others.
    pub routes: Vec<String>,
}

/// Why ENI resolution refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EniError {
    /// The ENI ID is not `eni-` followed by hexadecimal digits.
    Id,
    /// The metadata service did not answer for this path.
    Metadata(String),
    NotFound,
    /// More than one interface, or more than one network device, matches.
    Duplicate,
    /// The ENI is the instance's primary interface.
    Primary,
    /// A metadata or device attribute is missing or malformed, or the MAC is not permanent.
    Attribute(&'static str),
    /// The device is not on `ena`, or its PCI ID is not one the pinned driver supports.
    NotEna,
    /// The device carries the main IPv4 table's default route or an IPv6 default route, so it manages the host.
    Management,
    /// A route or neighbor table or the device's network state is
    /// unreadable, the MTU is zero or malformed, an address has a `brd`
    /// without a valid IPv4 address, a route has more than one next hop, an
    /// address or route holds a word `ip -batch` would not replay as itself,
    /// or the device's state lies outside the restoration domain: an address
    /// of another scope or in 127.0.0.0/8 (`"scope"`), a label other than the device's name,
    /// an alias such as `ens6:1` included (`"label"`), a `peer`
    /// (`"peer"`), `deprecated` (`"deprecated"`) or another word
    /// (`"addresses"`), a route in another table, a local-table entry of
    /// another address, a main-table route of type `local`, `broadcast` or
    /// `anycast`, a main-table route with a word outside the attributes
    /// `RouteWords::read` admits, or with no scope word and no gateway, or
    /// of type multicast with no scope word, or `default` through an IPv6
    /// gateway, or through a gateway no address or route that release
    /// replays first reaches, or through an IPv6 gateway on a device whose
    /// MTU is below 1280 or on a host whose new devices start with IPv6
    /// disabled, two main-table routes under one destination,
    /// type of service and metric, a route under those three of a host
    /// route of another device or of none, a host route the bind would
    /// remove, a multipath route with a next hop on the device, a route of
    /// the complete listing that names no device, a route line with
    /// whitespace outside ASCII, or an IPv6 route of the device other than
    /// the kernel's
    /// link-local entries (`"routes"`), an IPv4 rule naming the device, one of its
    /// altnames or one of its IPv4 addresses, or an IPv6 rule naming the
    /// device, one of its altnames or its link-local address (`"rules"`),
    /// an IPv6 address beyond one link-local address (`"ipv6"`), a master
    /// (`"master"`), or a device of its network namespace stacked on the
    /// device (`"upper"`); release
    /// replays the MTU, link state and IPv4 state.
    Unverifiable(&'static str),
    /// This next hop stays unresolved after `SOLICITS` rounds.
    NextHop(Ipv4Addr),
    /// The kernel's neighbor entry for this next hop is one the bind refuses
    /// and leaves in place: `NOARP`, a proxy entry, an unknown state, an
    /// entry with more than one state, an entry whose `lladdr` lacks a
    /// well-formed MAC, or a `REACHABLE` or `PERMANENT` entry with no MAC or
    /// one that is zero, multicast or broadcast.
    Neighbor(Ipv4Addr),
    /// Resolution passed one of its bounds: `"listing"` for a metadata
    /// listing, or a prefetched one, of more than [`LISTING_LIMIT`]
    /// interfaces, refused before any request for them starts, and
    /// `"deadline"` for a batch of requests that ended past
    /// [`DISCOVERY_LIMIT`].
    Limit(&'static str),
}

/// One distinct next hop while `next_hops` resolves it.
struct Hop {
    address: Ipv4Addr,
    mac: Option<[u8; 6]>,
    /// The most recent read that listed the hop's entry found it `STALE`,
    /// `DELAY`, `PROBE`, `FAILED`, `INCOMPLETE` or `NONE`.
    stale: bool,
}

/// Whether `mac` names one station: neither all zeros nor a group address,
/// which covers broadcast.
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

pub(crate) fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0; 6];
    let mut parts = text.trim().split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

pub(crate) fn format_mac(mac: &[u8; 6]) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

/// The network address and prefix of `a.b.c.d/p`, with the address masked
/// to its top `p` bits.
///
/// The ENI resolver and the mappings reader both admit CIDRs through this
/// function. It accepts a prefix of 1 through 30 written in ASCII digits,
/// so every subnet holds a network address, a router at network plus one
/// and at least one more host, and every mask shift `32 - p` stays below
/// 32. Returns `None` for text without a `/`, any other prefix or a
/// malformed address.
pub(crate) fn parse_cidr(text: &str) -> Option<(Ipv4Addr, u8)> {
    let text = text.trim();
    // The prefix follows the last `/`; an address that holds another `/`
    // fails to parse.
    let slash = text.bytes().rposition(|byte| byte == b'/')?;
    let (address, prefix) = (&text[..slash], &text.as_bytes()[slash + 1..]);
    if prefix.is_empty() {
        return None;
    }
    let prefix = prefix
        .iter()
        .try_fold(0u8, |prefix, &digit| {
            let digit = digit.is_ascii_digit().then(|| digit - b'0')?;
            prefix.checked_mul(10)?.checked_add(digit)
        })
        .filter(|prefix| (1..=30).contains(prefix))?;
    let address: Ipv4Addr = address.parse().ok()?;
    let mask = u32::MAX << (32 - prefix);
    Some((Ipv4Addr::from(u32::from(address) & mask), prefix))
}

/// Whether `ip` lies inside subnet `cidr`.
fn in_subnet(cidr: (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    let mask = u32::MAX << (32 - cidr.1);
    u32::from(ip) & mask == u32::from(cidr.0)
}

/// The address `ip` is reached through from subnet `cidr`: itself inside the subnet, the subnet's router outside it.
pub(crate) fn next_hop(cidr: (Ipv4Addr, u8), ip: Ipv4Addr) -> Ipv4Addr {
    if in_subnet(cidr, ip) {
        ip
    } else {
        Ipv4Addr::from(u32::from(cidr.0) + 1)
    }
}

impl NetState {
    /// Whether `other` records the same configuration: the MTU, the link
    /// state, and the same addresses and routes in any order.
    pub(crate) fn same_configuration(&self, other: &Self) -> bool {
        fn sorted(items: &[String]) -> Vec<&str> {
            let mut items: Vec<&str> = items.iter().map(String::as_str).collect();
            items.sort_unstable();
            items
        }
        let Self {
            mtu,
            up,
            addresses,
            routes,
        } = self;
        let same = |items: &[String], others: &[String]| {
            items == others || sorted(items) == sorted(others)
        };
        (*mtu, *up) == (other.mtu, other.up)
            && same(addresses, &other.addresses)
            && same(routes, &other.routes)
    }

    /// Whether one of the device's addresses is `ip`.
    pub(crate) fn holds(&self, ip: Ipv4Addr) -> bool {
        self.addresses.iter().any(|address| {
            address
                .split('/')
                .next()
                .and_then(|address| address.parse().ok())
                == Some(ip)
        })
    }
}

/// `get_all` returns answers in `paths` order and the result of `during`,
/// which runs on the calling thread while the first batch is out.
fn get_all<T>(
    metadata: &dyn Metadata,
    paths: &[String],
    in_time: impl Fn() -> Result<(), EniError>,
    during: impl FnOnce() -> T,
) -> Result<(Vec<io::Result<String>>, T), EniError> {
    let mut batches = paths.chunks(REQUESTS_AT_ONCE);
    let (mut answers, ran) = get_batch(metadata, batches.next().unwrap_or_default(), during);
    for batch in batches {
        in_time()?;
        answers.extend(get_batch(metadata, batch, || ()).0);
    }
    Ok((answers, ran))
}

/// The answer to each of `paths`, in order, with every request sent at once
/// from its own thread, and the result of `during`, which runs on the
/// calling thread while the requests are out; a request whose thread cannot
/// start fails with the spawn error.
fn get_batch<T>(
    metadata: &dyn Metadata,
    paths: &[String],
    during: impl FnOnce() -> T,
) -> (Vec<io::Result<String>>, T) {
    thread::scope(|scope| {
        let requests: Vec<_> = paths
            .iter()
            .map(|path| requester(path).spawn_scoped(scope, move || metadata.get(path)))
            .collect();
        let ran = during();
        let answers = requests
            .into_iter()
            .map(|request| match request {
                Ok(handle) => handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                Err(error) => Err(error),
            })
            .collect();
        (answers, ran)
    })
}

#[cfg(test)]
thread_local! {
    /// The path whose request thread a test makes fail to start: its
    /// builder asks for a 4 EiB stack, past any user virtual address space,
    /// which the kernel refuses under every overcommit setting.
    pub(crate) static UNSTARTABLE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// The builder of `path`'s request thread. Under test, the builder for the
/// [`UNSTARTABLE`] path requests a stack the kernel refuses.
fn requester(path: &str) -> thread::Builder {
    let builder = thread::Builder::new();
    #[cfg(test)]
    if UNSTARTABLE.with_borrow(|unstartable| unstartable.as_deref() == Some(path)) {
        return builder.stack_size(1 << 62);
    }
    let _ = path;
    builder
}

impl Host {
    /// Resolves `eni` through `metadata` to its one network device and PCI
    /// function on `ena`. Independent requests run concurrently, at most
    /// `REQUESTS_AT_ONCE` in flight: every listed interface's ID, then the
    /// matched interface's fields. Their answers are checked in listing and
    /// field order.
    ///
    /// # Errors
    ///
    /// [`EniError`] naming the first failed check.
    pub fn resolve_eni(&self, metadata: &dyn Metadata, eni: &str) -> Result<Eni, EniError> {
        self.resolve_eni_while(&SysfsKernel, metadata, eni, None, |_| ())
            .map(|(eni, (), _)| eni)
    }

    /// Resolves `eni` as [`resolve_eni`](Self::resolve_eni) does, and runs
    /// `during`, followed by the device checks of
    /// [`ena_function`](Self::ena_function), on the network device of the
    /// interface the ENI ID names, when exactly one device carries its MAC,
    /// while that interface's fields are fetched. The result of `during` and
    /// what the resolution saw return with the ENI.
    ///
    /// With `seen`, the listing, the ID of each interface `seen` lists and
    /// the fields of the interface it matched go out in one round, and the
    /// device work runs on the one device carrying `seen`'s MAC while that
    /// round is out. When the listing and match remain unchanged, the
    /// prefetched IDs and fields serve, and that device work serves if the
    /// same one device still carries the matched MAC; otherwise it runs again
    /// on the device the resolution locates, so `during` runs at most twice.
    ///
    /// The resolution refuses once a round of requests ends past
    /// [`DISCOVERY_LIMIT`] from its start on `clock`'s monotonic time, and
    /// refuses a listing, or a prefetched one, of more than
    /// [`LISTING_LIMIT`] interfaces before any request for them starts.
    ///
    /// The device's function is read under the name the listing of the
    /// class gave. A rename can hand that name to another device between
    /// the listing and the read, and hand it back after, so the function is
    /// returned only when one device, read once the function is known,
    /// carries the ENI's MAC and sits on that function
    /// ([`Host::netdev_carries_on`]).
    ///
    /// # Errors
    ///
    /// As [`resolve_eni`](Self::resolve_eni), and `Unverifiable("class/net")`
    /// when the device under the located name, once its function is read,
    /// does not carry the ENI's MAC on that function.
    pub(crate) fn resolve_eni_while<R>(
        &self,
        clock: &dyn Kernel,
        metadata: &dyn Metadata,
        eni: &str,
        seen: Option<&Sighting>,
        during: impl Fn(&str) -> R,
    ) -> Result<(Eni, R, Sighting), EniError> {
        if !is_eni_id(eni) {
            return Err(EniError::Id);
        }
        let deadline = clock.now() + DISCOVERY_LIMIT;
        let in_time = || {
            (clock.now() <= deadline)
                .then_some(())
                .ok_or(EniError::Limit("deadline"))
        };
        let base = "network/interfaces/macs/";
        let names = [
            "device-number",
            "network-card",
            "local-ipv4s",
            "subnet-id",
            "subnet-ipv4-cidr-block",
        ];
        let id_path = |mac: &[u8; 6]| format!("{base}{}/interface-id", format_mac(mac));
        let field_paths =
            |mac: &[u8; 6]| names.map(|name| format!("{base}{}/{name}", format_mac(mac)));
        let answer = |path: &String, body: &io::Result<String>| {
            body.as_ref()
                .map(|text| text.trim().to_owned())
                .map_err(|_| EniError::Metadata(path.clone()))
        };
        let mut early = vec![base.to_owned()];
        if let Some(seen) = seen {
            if seen.listed.len() > LISTING_LIMIT {
                return Err(EniError::Limit("listing"));
            }
            early.extend(seen.listed.iter().map(id_path));
            early.extend(field_paths(&seen.mac));
        }
        // The device's work, `during` first, then its function on `ena`. The
        // function is read under the name the listing gave, so it stands only
        // when the device then under that name carries the MAC the listing
        // matched and sits on that function.
        let on_device = |mac: [u8; 6], netdev: &String| {
            let ran = during(netdev);
            let bdf = self.ena_function(netdev).and_then(|bdf| {
                if self.netdev_carries_on(netdev, mac, &bdf) {
                    Ok(bdf)
                } else {
                    Err(EniError::Unverifiable("class/net"))
                }
            });
            (netdev.clone(), ran, bdf)
        };
        let early_locate = || match seen.map(|seen| (seen.mac, self.netdevs_with_mac(seen.mac))) {
            Some((mac, Ok(found))) => match found.as_slice() {
                [netdev] => Some(on_device(mac, netdev)),
                _ => None,
            },
            _ => None,
        };
        let (mut answers, early_located) = get_all(metadata, &early, in_time, early_locate)?;
        in_time()?;
        let mut ahead = answers.split_off(1);
        let listing = answer(&early[0], &answers[0])?;
        if listing.lines().count() > LISTING_LIMIT {
            return Err(EniError::Limit("listing"));
        }
        let listed = listing
            .lines()
            .map(|line| {
                parse_mac(line.trim().trim_end_matches('/')).ok_or(EniError::Attribute("mac"))
            })
            .collect::<Result<Vec<_>, EniError>>()?;
        let paths: Vec<String> = listed.iter().map(id_path).collect();
        let seen = seen.filter(|seen| seen.listed == listed);
        let ids = match seen {
            Some(_) => ahead.drain(..listed.len()).collect(),
            None => get_all(metadata, &paths, in_time, || ())?.0,
        };
        in_time()?;
        let mut matched = None;
        for ((path, body), mac) in paths.iter().zip(&ids).zip(&listed) {
            if answer(path, body)? == eni && matched.replace(*mac).is_some() {
                return Err(EniError::Duplicate);
            }
        }
        let mac = matched.ok_or(EniError::NotFound)?;
        let paths = field_paths(&mac);
        let devices = self.netdevs_with_mac(mac);
        let locate = || match devices.as_deref() {
            Ok([netdev]) => Some(on_device(mac, netdev)),
            _ => None,
        };
        let (bodies, located) = match seen {
            Some(seen) if seen.mac == mac => {
                let located = match (early_located, devices.as_deref()) {
                    (Some(early), Ok([netdev])) if early.0 == *netdev => Some(early),
                    _ => locate(),
                };
                (ahead, located)
            }
            _ => get_all(metadata, &paths, in_time, locate)?,
        };
        in_time()?;
        let field = |index: usize| answer(&paths[index], &bodies[index]);
        let number = |index: usize| -> Result<u32, EniError> {
            field(index)?
                .parse()
                .map_err(|_| EniError::Attribute(names[index]))
        };
        let device_number = number(0)?;
        // A missing `network-card` entry reads as card 0.
        let network_card = match &bodies[1] {
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            _ => number(1)?,
        };
        if device_number == 0 && network_card == 0 {
            return Err(EniError::Primary);
        }
        // The dedicated ENI carries exactly one address, in its own subnet.
        let addresses = field(2)?;
        let mut addresses = addresses
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let ipv4: Ipv4Addr = match (addresses.next(), addresses.next()) {
            (Some(only), None) => only.parse().ok(),
            _ => None,
        }
        .ok_or(EniError::Attribute("local-ipv4s"))?;
        let subnet = field(3)?;
        let cidr = parse_cidr(&field(4)?).ok_or(EniError::Attribute("subnet-ipv4-cidr-block"))?;
        if !in_subnet(cidr, ipv4) {
            return Err(EniError::Attribute("local-ipv4s"));
        }
        let (netdev, ran, bdf) = match (devices, located) {
            (Ok(_), Some(located)) => located,
            (Ok(found), None) if found.is_empty() => return Err(EniError::NotFound),
            (Ok(_), None) => return Err(EniError::Duplicate),
            (Err(_), _) => return Err(EniError::Unverifiable("class/net")),
        };
        let bdf = bdf?;
        let eni = Eni {
            id: eni.to_owned(),
            mac,
            ipv4,
            subnet,
            cidr,
            device_number,
            network_card,
            netdev,
            bdf,
        };
        Ok((eni, ran, Sighting { listed, mac }))
    }

    /// The PCI function of `netdev`, a device with a permanent MAC on `ena`
    /// with a supported PCI ID, carrying neither the main IPv4 table's
    /// default route nor an IPv6 default route.
    ///
    /// # Errors
    ///
    /// `Attribute("addr_assign_type")` for a MAC the host assigned or
    /// changed, or an unreadable assignment type,
    /// `Attribute("device")` for a device without a PCI function, `NotEna`
    /// for another driver or PCI ID, `Management` for a default route, or
    /// `Unverifiable` for an unreadable route table, or an IPv6 route table
    /// of which no two listings under a still census agreed (`"ipv6_route"`).
    ///
    /// The route tables and `proc/net/dev` name a device by the name it has
    /// when they are read, so a device renamed after its sysfs entries were
    /// read has its routes under a name this search does not look for. The
    /// kernel changes that name first, then renames the device's sysfs
    /// entry and sends a uevent, which `sys/kernel/uevent_seqnum` counts, all
    /// before another rename starts. A pass is therefore returned only when
    /// `proc/net/dev`, read after the route tables, still lists `netdev`
    /// and the counter reads the same before and after the pass: a rename
    /// that left the name before the route read either still holds the
    /// device under its new name in that listing, or sent its uevent before
    /// a later rename gave the name back. A pass that fails either test is
    /// read again, at most [`NAME_PASSES`] in all; `Unverifiable("route")`
    /// when the counter or `proc/net/dev` is unreadable, the counter is not a
    /// number, or every pass failed a test.
    fn ena_function(&self, netdev: &str) -> Result<String, EniError> {
        let counter = self.sys.join("kernel/uevent_seqnum");
        let sequence = || {
            self.kernel_text(&counter)
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or(EniError::Unverifiable("route"))
        };
        let mut before = sequence()?;
        for _pass in 0..NAME_PASSES {
            let bdf = self.ena_function_pass(netdev)?;
            let named = self.holds_name(netdev)?;
            let after = sequence()?;
            if named && after == before {
                return Ok(bdf);
            }
            before = after;
        }
        Err(EniError::Unverifiable("route"))
    }

    /// Whether `proc/net/dev`, which lists each device by the name it has
    /// when the listing is read, lists `netdev`.
    ///
    /// # Errors
    ///
    /// `Unverifiable("route")` when `proc/net/dev` is unreadable.
    fn holds_name(&self, netdev: &str) -> Result<bool, EniError> {
        let devices = self
            .kernel_text(&self.proc.join("net/dev"))
            .ok_or(EniError::Unverifiable("route"))?;
        // Two header lines precede one `name: counters` line a device.
        Ok(devices.lines().skip(2).any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.trim() == netdev)
        }))
    }

    /// The [`settled_table`] of `table` under `proc/net`, read where no
    /// mount [covers](Self::kernel) the table or the census that settles
    /// it.
    ///
    /// # Errors
    ///
    /// As [`settled_table`], with `NotFound` for a table the kernel does
    /// not have, and an error of another kind when a mount covers the table
    /// or the census or the mount table cannot be read.
    fn shown_table(&self, table: &str) -> io::Result<String> {
        let net = self.proc.join("net");
        let mounts = self.mount_table()?;
        for entry in [table, "rt6_stats"] {
            self.shown(&mounts, &net.join(entry))?;
        }
        settled_table(&net, table)
    }

    /// One pass of [`ena_function`](Self::ena_function): the device's sysfs
    /// entries, then the route tables, each read by the name `netdev`.
    fn ena_function_pass(&self, netdev: &str) -> Result<String, EniError> {
        // A MAC the host assigned or changed could stand for another interface's.
        let permanent = self.kernel_text(
            &self
                .sys
                .join("class/net")
                .join(netdev)
                .join("addr_assign_type"),
        );
        if permanent.as_deref() != Some("0") {
            return Err(EniError::Attribute("addr_assign_type"));
        }
        let bdf = self
            .netdev_function(netdev)
            .ok_or(EniError::Attribute("device"))?;
        if self.driver(&bdf).as_deref() != Some(ENA_DRIVER)
            || !self.pci_id(&bdf).is_some_and(|id| ENA_PCI.contains(&id))
        {
            return Err(EniError::NotEna);
        }
        let routes = self
            .kernel_text(&self.proc.join("net/route"))
            .ok_or(EniError::Unverifiable("route"))?;
        let default = routes.lines().skip(1).any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(netdev) && fields.next() == Some("00000000")
        });
        // A host without IPv6 has no IPv6 route table; any other read failure leaves the routes unknown.
        let v6_table = match self.shown_table("ipv6_route") {
            Ok(table) => Some(table),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(EniError::Unverifiable("ipv6_route")),
        };
        let v6_default = v6_table.is_some_and(|table| {
            table.lines().any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                fields.len() == 10
                    && fields[0] == "0".repeat(32)
                    && fields[1] == "00"
                    && fields[9] == netdev
            })
        });
        if default || v6_default {
            return Err(EniError::Management);
        }
        Ok(bdf)
    }

    /// The ENI device's MTU, link state, IPv4 addresses and main-table routes.
    ///
    /// # Errors
    ///
    /// `net_state` returns `Unverifiable` when the device flags are unreadable
    /// or malformed, the IPv6 address table is unreadable or malformed or no
    /// two of its listings under a still census agreed, the MTU is missing, zero,
    /// non-numeric or above `u32::MAX` (`"mtu"`), the `ip` read fails or
    /// prints malformed output, an address has a `brd` without a valid IPv4
    /// address (`"addresses"`), a route has more than one next hop, an
    /// address or route holds a word `ip -batch` cannot replay unchanged, two
    /// routes share one replace key, the device has a master or carries a device of its network namespace
    /// stacked on it, its state lies outside the restoration domain,
    /// with the detail [`EniError::Unverifiable`] names, or the host's uevent
    /// counter is unreadable, is not a number or moved while the state was
    /// read (`"name"`).
    pub fn net_state(&self, kernel: &dyn Kernel, netdev: &str) -> Result<NetState, EniError> {
        let shows = IpShows::start(kernel).map_err(|_| EniError::Unverifiable("ip"))?;
        self.net_state_from(shows, netdev)
    }

    /// The device's network state, as [`net_state`](Self::net_state)
    /// returns it, with the IPv4 reads through `ip IP_SHOW`, and the IPv6
    /// reads and the device's link line through `ip IP_SHOW6`.
    ///
    /// The address and route tables, and `ip`, name a device by the name it
    /// has when they are read, so a device renamed while its state is read
    /// has entries under a name this read does not look for. The kernel
    /// sends a uevent when a network device is renamed, and
    /// `sys/kernel/uevent_seqnum` counts every uevent sent on the host, so a
    /// state is returned only when the counter reads the same before and
    /// after the read. `ip` runs once, so a read the counter moved across
    /// refuses and is not repeated.
    ///
    /// # Errors
    ///
    /// As [`net_state`](Self::net_state).
    pub(crate) fn net_state_from(
        &self,
        shows: IpShows<'_>,
        netdev: &str,
    ) -> Result<NetState, EniError> {
        let counter = self.sys.join("kernel/uevent_seqnum");
        let sequence = || {
            self.kernel_text(&counter)
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or(EniError::Unverifiable("name"))
        };
        let before = sequence()?;
        let state = self.net_state_pass(shows, netdev)?;
        if sequence()? != before {
            return Err(EniError::Unverifiable("name"));
        }
        Ok(state)
    }

    /// The one pass of [`net_state_from`](Self::net_state_from): the
    /// device's sysfs entries, the IPv6 address table and the `ip`
    /// listings, each read by the name `netdev`.
    fn net_state_pass(&self, shows: IpShows<'_>, netdev: &str) -> Result<NetState, EniError> {
        let IpShows { ip, ip6 } = shows;
        // A listing by device holds the device's routes without their `dev` word, and before `ip` 6.10 leaves
        // out each route that names its device only in a next hop or a nexthop object, or names none. The
        // complete listing holds every route of the host with its device. The device's link line stands
        // between the two, so each route line is read as the listing it belongs to prints it.
        let complete: &[&str] = &["route", "show", "table", "all"];
        let link: &[&str] = &["link", "show", "dev", netdev];
        let input = batch(
            [
                &["addr", "show", "dev", netdev][..],
                &["route", "show", "table", "all", "dev", netdev],
                link,
                complete,
                &["rule", "show"],
            ]
            .into_iter()
            .map(|command| command.iter().copied()),
        );
        // Disabling IPv6 removes `net/if_inet6`, so a missing table reads
        // as empty, and `ip` then refuses IPv6 route and rule reads, so the
        // capture reads the link line alone.
        let v6_table = self.proc.join("net/if_inet6");
        let ipv6 = !matches!(
            self.kernel(&v6_table).and_then(fs::symlink_metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );
        let reads6: &[&[&str]] = &[
            &["route", "show", "table", "all", "dev", netdev],
            &["rule", "show"],
            link,
            complete,
        ];
        let input6 = batch(
            reads6[if ipv6 { 0..4 } else { 2..3 }]
                .iter()
                .map(|command| command.iter().copied()),
        );
        let net = self.sys.join("class/net").join(netdev);
        // Release replays no master membership, so a port of a bond, bridge or VRF refuses.
        // A master link a mount hides is no absence.
        let master = net.join("master");
        if !matches!(
            self.kernel(&master).and_then(fs::symlink_metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        ) {
            return Err(EniError::Unverifiable("master"));
        }
        // Sysfs links each device stacked on this one in its network namespace as `upper_<name>` in this
        // directory. An entry that cannot be read refuses as a link does, and a missing directory refuses
        // at the flags.
        let stacked = match self.kernel(&net).and_then(fs::read_dir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            entries => entries.and_then(|mut entries| {
                entries.try_fold(false, |found, entry| {
                    let upper = entry?.file_name().as_encoded_bytes().starts_with(b"upper_");
                    io::Result::Ok(found || upper)
                })
            }),
        };
        if !matches!(stacked, Ok(false)) {
            return Err(EniError::Unverifiable("upper"));
        }
        let flags = self
            .kernel_text(&net.join("flags"))
            .and_then(|text| u32::from_str_radix(text.trim_start_matches("0x"), 16).ok())
            .ok_or(EniError::Unverifiable("flags"))?;
        let mtu = self
            .kernel_text(&net.join("mtu"))
            .and_then(|text| text.parse::<NonZeroU32>().ok())
            .ok_or(EniError::Unverifiable("mtu"))?;
        // One listing can leave out an address the device holds throughout, so the table is settled as the
        // route table is.
        let v6_addresses = if ipv6 {
            self.shown_table("if_inet6")
                .map_err(|_| EniError::Unverifiable("addresses"))?
        } else {
            String::new()
        };
        let mut link_local = None;
        for line in v6_addresses.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [address, _, _, scope, _, device] = fields[..] else {
                return Err(EniError::Unverifiable("addresses"));
            };
            let scope =
                u32::from_str_radix(scope, 16).map_err(|_| EniError::Unverifiable("addresses"))?;
            let address = u128::from_str_radix(address, 16)
                .map_err(|_| EniError::Unverifiable("addresses"))?;
            if device == netdev {
                if link_local.is_some() || scope & IPV6_LOCAL_SCOPES != IPV6_LINK_SCOPE {
                    return Err(EniError::Unverifiable("ipv6"));
                }
                link_local = Some(Ipv6Addr::from(address));
            }
        }
        // A device name `batch` cannot pass refuses here, after the sysfs and
        // `if_inet6` refusals.
        let input6 = input6.ok_or(EniError::Unverifiable("ip"))?;
        let input = input.ok_or(EniError::Unverifiable("ip"))?;
        // Both programs hold their commands from here, so `ip IP_SHOW6` can
        // read the kernel while this thread reads and admits the IPv4
        // output.
        let (ip, ip6) = (ip.feed(&input), ip6.feed(&input6));
        let output = ip.finish().map_err(|_| EniError::Unverifiable("ip"))?;
        let (mut addresses, mut rules) = (Vec::new(), Vec::new());
        // What the kernel derives each address's local-table entries from.
        let mut assigned = Vec::new();
        let (mut admitted, mut host_routes) = (Vec::new(), Vec::new());
        // Whether the link line has passed, so the line belongs to the complete listing.
        let mut complete = false;
        // The words of the route line being read. One buffer serves every line.
        let mut listed: Vec<&str> = Vec::new();
        // `ip` ends a word at ASCII whitespace alone, and this read ends one at any whitespace. The vertical
        // tab is the one ASCII character that is whitespace to this read alone, so in a listing of other
        // ASCII characters both end every word at the same place.
        let plain = output.is_ascii() && !output.as_bytes().contains(&0x0b);
        for line in lines(&output) {
            let first = if plain {
                line.split_ascii_whitespace().next()
            } else {
                line.split_whitespace().next()
            };
            // A line of whitespace holds nothing.
            let Some(first) = first else {
                continue;
            };
            // A link line, an address and a rule print led by an index or a priority, `3:` or `32765:`, and
            // a route by its type or destination.
            let led = priority(first);
            if led && link_line(line, netdev) {
                complete = true;
                continue;
            }
            // A name that holds a space outside ASCII whitespace is one word to `ip` and several to this
            // read. An address or route line with one refuses.
            let spaced = !plain
                && line
                    .chars()
                    .any(|c| c.is_whitespace() && !c.is_ascii_whitespace());
            // An address prints led by its device's index, `3: ens6    inet
            // 10.0.1.5/24 ...`, and a rule by its priority, `32765:\tfrom
            // 10.0.1.5 lookup 7`, whose words exclude `inet`.
            if led {
                match address(line, netdev)? {
                    Some(_) if spaced => return Err(EniError::Unverifiable("addresses")),
                    Some(address) => {
                        assigned.extend(Assigned::read(&address));
                        addresses.push(address);
                    }
                    None => rules.push(line),
                }
                continue;
            }
            // A multipath route prints its next hops after its first line's words, which a replace of those words cannot restore.
            if spaced || line.starts_with(char::is_whitespace) {
                return Err(EniError::Unverifiable("routes"));
            }
            // The line holds no space outside ASCII whitespace, so the ASCII split yields the same words.
            listed.clear();
            listed.extend(line.split_ascii_whitespace());
            let device_less = listed
                .first()
                .is_some_and(|kind| DEVICE_LESS.contains(kind));
            let route = RouteWords::read(&listed, !device_less && !complete)
                .ok_or(EniError::Unverifiable("routes"))?;
            // A route of these types belongs to no device, so the capture records none. The bind removes one
            // all the same when its nexthop object is on the device, which the listing shows only by naming
            // another device. Each other one stays, a host route.
            if device_less {
                if route.object && route.device.is_none_or(|device| device == netdev) {
                    return Err(EniError::Unverifiable("routes"));
                }
                host_routes.push(route);
                continue;
            }
            // The complete listing names the device of each route but a multipath one, which names a device
            // in each next hop, and one through a nexthop object on a host that lists no device for an object.
            // The bind removes a multipath route whole with one next hop on the device, and a route that
            // names no device may be the device's. The listing by device holds each route that names the
            // device. Each other route belongs to another device and stays, like a host route.
            if complete {
                let hop = route.hops.contains(&netdev);
                match route.device {
                    _ if hop => return Err(EniError::Unverifiable("routes")),
                    None if route.hops.is_empty() => return Err(EniError::Unverifiable("routes")),
                    Some(device) if device == netdev => {}
                    _ => host_routes.push(route),
                }
                continue;
            }
            // A route of any table other than main lists a `table` attribute.
            if route.table.is_some() {
                if !derived_entry(&assigned, &route.words) {
                    return Err(EniError::Unverifiable("routes"));
                }
                continue;
            }
            if !route.replays_unchanged() {
                return Err(EniError::Unverifiable("routes"));
            }
            admitted.push(route);
        }
        // Release replays each route as `route replace`, which overwrites the route under the same key: another
        // recorded route, or a host route, which belongs to another device or to none. The kernel takes each gateway only
        // through a route release has replayed by then, and an IPv6 gateway only on a device with IPv6
        // enabled: one at the recorded MTU, which release restores before the routes, on a host whose new
        // devices start with IPv6 enabled, as the returned device does.
        let ipv6_by_default = || {
            self.kernel_text(&self.proc.join("sys/net/ipv6/conf/default/disable_ipv6"))
                .as_deref()
                == Some("0")
        };
        let reached = || {
            let reach = Reach::of(&admitted, &addresses, &host_routes, &rules);
            admitted
                .iter()
                .enumerate()
                .all(|(place, route)| reach.reaches_gateway(route, place))
        };
        let mut keys: Vec<_> = admitted.iter().map(RouteWords::key).collect();
        keys.sort_unstable();
        // The kernel removes a main-table route with the address its `src` names, on whatever device.
        let mut locals: Vec<&str> = addresses
            .iter()
            .filter_map(|address| address.split(['/', ' ']).next())
            .collect();
        locals.sort_unstable();
        let held = |host: &RouteWords| {
            host.table.is_none()
                && host
                    .source
                    .is_some_and(|source| locals.binary_search(&source).is_ok())
        };
        // The keys stand in order of their destinations, so the keys of one destination are one run.
        let overwritten = |host: &RouteWords| {
            let from = keys.partition_point(|key| key.0 < host.destination);
            keys[from..]
                .iter()
                .take_while(|key| key.0 == host.destination)
                .any(|key| host.replaced_under(*key))
        };
        if keys.windows(2).any(|pair| pair[0] == pair[1])
            || host_routes.iter().any(overwritten)
            || host_routes.iter().any(held)
            || !reached()
            || (admitted.iter().any(|route| route.inet6)
                && (mtu.get() < IPV6_MIN_MTU || !ipv6_by_default()))
        {
            return Err(EniError::Unverifiable("routes"));
        }
        let routes: Vec<String> = admitted.iter().map(|route| route.words.join(" ")).collect();
        let output6 = ip6.finish().map_err(|_| EniError::Unverifiable("ip"))?;
        let names = ipv6_state(&output6, netdev, link_local)?;
        // Release replays the main table alone, so a rule naming the device
        // by any of its names, or one of its addresses, refuses.
        let mut selected: Vec<&str> = addresses
            .iter()
            .filter_map(|address| address.split('/').next())
            .collect();
        selected.sort_unstable();
        let named = |word: &str| {
            names.contains(&word)
                || word
                    .split('/')
                    .next()
                    .is_some_and(|word| selected.binary_search(&word).is_ok())
        };
        if rules
            .iter()
            .any(|rule| rule.split_whitespace().skip(1).any(named))
        {
            return Err(EniError::Unverifiable("rules"));
        }
        // Release replays each address and route through `ip -batch`. A recorded route is its words
        // joined by spaces, and no word holds whitespace, so release splits it into these words.
        if batch(addresses.iter().map(|address| address.split_whitespace())).is_none() {
            return Err(EniError::Unverifiable("addresses"));
        }
        if batch(admitted.iter().map(|route| route.words.iter().copied())).is_none() {
            return Err(EniError::Unverifiable("routes"));
        }
        Ok(NetState {
            mtu,
            up: flags & IFF_UP != 0,
            addresses,
            routes,
        })
    }

    /// The MAC of the next hop toward each of `peers`, from the kernel's
    /// neighbor entries on the ENI's device. A `REACHABLE` entry is the
    /// kernel's current confirmation, and a `PERMANENT` one is configuration
    /// the deployment trusts; either gives its MAC at once. Every other hop
    /// gets up to `SOLICITS` rounds. The first read selects the entries it
    /// finds `STALE`, `DELAY`, `PROBE`, `FAILED`, `INCOMPLETE` or `NONE`, and
    /// one `ip -batch` flushes them before the first solicitation, so each
    /// flushed hop's next entry is a fresh resolution. Each round solicits
    /// every unresolved hop once and reads the table at `READS` offsets after
    /// its solicitations, stopping once every hop resolves. One read serves
    /// every hop: hops all resolved at the first read take one read, and hops
    /// resolved at the first read after the solicitations take two.
    ///
    /// Flushing an entry and soliciting change the ENI's neighbor state. A
    /// bind refused before its record writes no driver attribute but can
    /// leave that state changed. The MACs hold for the owner's run: a gateway or peer that
    /// changes identity later needs a controlled refresh and an endpoint
    /// restart.
    ///
    /// # Errors
    ///
    /// `NextHop` naming the hop of the first peer without a MAC after the
    /// rounds; `Neighbor` for a hop whose entry the bind refuses as it is;
    /// `Unverifiable("neighbors")` when the table cannot be read, names an
    /// entry by a malformed address, or is on a device whose name `batch`
    /// cannot pass to `ip -batch` as one word.
    pub fn next_hops(
        &self,
        kernel: &dyn Kernel,
        eni: &Eni,
        peers: &[Ipv4Addr],
    ) -> Result<Vec<(Ipv4Addr, [u8; 6])>, EniError> {
        let mut hops: Vec<Hop> = Vec::new();
        for &peer in peers {
            let hop = next_hop(eni.cidr, peer);
            if !hops.iter().any(|known| known.address == hop) {
                hops.push(Hop {
                    address: hop,
                    mac: None,
                    stale: false,
                });
            }
        }
        let unresolved = |hops: &[Hop]| hops.iter().any(|hop| hop.mac.is_none());
        read_neighbors(kernel, &eni.netdev, &mut hops, kernel.now())?;
        let stale: Vec<String> = hops
            .iter()
            .filter(|hop| hop.stale)
            .map(|hop| hop.address.to_string())
            .collect();
        let flushes = stale.iter().map(|address| {
            let netdev = eni.netdev.as_str();
            ["neigh", "flush", "to", address.as_str(), "dev", netdev]
        });
        // The flushes run before any solicitation, so an entry a solicitation
        // starts stays. A flush of an absent entry succeeds, so the batch
        // continues past it. A failed flush stops the batch, and the rounds
        // then solicit and read the hops whose entries it leaves.
        if !stale.is_empty() {
            let input = batch(flushes).ok_or(EniError::Unverifiable("neighbors"))?;
            let _flushed = kernel.run("ip", &["-4", "-batch", "-"], &input);
        }
        for _ in 0..SOLICITS {
            if !unresolved(&hops) {
                break;
            }
            for hop in hops.iter().filter(|hop| hop.mac.is_none()) {
                // A failed send leaves the hop unresolved, as one that does not answer.
                let _sent = kernel.solicit(&eni.netdev, hop.address);
            }
            let solicited = kernel.now();
            for after in READS {
                read_neighbors(kernel, &eni.netdev, &mut hops, solicited + after)?;
                if !unresolved(&hops) {
                    break;
                }
            }
        }
        peers
            .iter()
            .map(|&peer| {
                let hop = next_hop(eni.cidr, peer);
                hops.iter()
                    .find(|known| known.address == hop)
                    .and_then(|known| known.mac)
                    .map(|mac| (peer, mac))
                    .ok_or(EniError::NextHop(hop))
            })
            .collect()
    }
}

/// Reads every proxy entry on `netdev`, then every neighbor entry on it in
/// any state (`nud all`), no earlier than `at`, and updates each unresolved
/// hop of `hops` from its entries. `ip` prints proxy entries only for
/// `neigh show proxy`, as the address and the word `proxy`, so that listing
/// runs first in the same batch: a hop with a proxy entry refuses before an
/// ordinary entry could resolve it. A hop absent from both listings stays
/// unresolved, as does one whose
/// entry is `STALE`, `DELAY`, `PROBE`, `FAILED`, `INCOMPLETE` or `NONE`;
/// `ip` prints kernel state zero, `NONE`, as an empty state list. A refused
/// entry returns `Neighbor`. An unreadable listing, an entry named by a
/// malformed address, or a `netdev` that `batch` cannot pass as one word
/// returns `Unverifiable("neighbors")`.
fn read_neighbors(
    kernel: &dyn Kernel,
    netdev: &str,
    hops: &mut [Hop],
    at: Instant,
) -> Result<(), EniError> {
    let unreadable = || EniError::Unverifiable("neighbors");
    let proxies = ["neigh", "show", "proxy", "dev", netdev];
    let entries = ["neigh", "show", "dev", netdev, "nud", "all"];
    let show = batch([&proxies[..], &entries[..]].map(|command| command.iter().copied()))
        .ok_or_else(unreadable)?;
    let table = kernel
        .run_at("ip", &["-4", "-o", "-batch", "-"], &show, at)
        .map_err(|_| unreadable())?;
    for line in table.lines().filter(|line| !line.trim().is_empty()) {
        // `ip` ends a word at ASCII whitespace alone, so a protocol name holding
        // a space outside ASCII stays one word and gives the entry no second
        // `lladdr` or state.
        let mut words = line.split_ascii_whitespace();
        let address: Ipv4Addr = words
            .next()
            .and_then(|word| word.parse().ok())
            .ok_or_else(unreadable)?;
        let Some(hop) = hops
            .iter_mut()
            .find(|hop| hop.address == address && hop.mac.is_none())
        else {
            continue;
        };
        let refused = || EniError::Neighbor(address);
        let (mut mac, mut proxy, mut states) = (None, false, Vec::new());
        while let Some(word) = words.next() {
            match word {
                "lladdr" => mac = Some(words.next().and_then(parse_mac).ok_or_else(refused)?),
                "proxy" => proxy = true,
                "router" | "extern_learn" | "offload" | "managed" | "extern_valid" => {}
                "proto" => {
                    words.next().ok_or_else(refused)?;
                }
                state => states.push(state),
            }
        }
        // An empty state list is how `ip` prints kernel state zero, `NONE`.
        let state = match states[..] {
            [] => "NONE",
            [state] => state,
            _ => return Err(refused()),
        };
        if proxy {
            return Err(refused());
        }
        hop.stale = false;
        match state {
            "REACHABLE" | "PERMANENT" => {
                hop.mac = Some(mac.filter(|&mac| unicast(mac)).ok_or_else(refused)?);
            }
            "STALE" | "DELAY" | "PROBE" | "FAILED" | "INCOMPLETE" | "NONE" => hop.stale = true,
            _ => return Err(refused()),
        }
    }
    Ok(())
}

/// The lines of `text`, each up to a newline or the text's end, from one
/// search of the text for newlines. A carriage return before a newline
/// stays at its line's end, and a text that ends in a newline yields an
/// empty last line.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let mut start = 0;
    memchr::memchr_iter(b'\n', text.as_bytes())
        .chain([text.len()])
        .map(move |end| {
            let line = &text[start.min(end)..end];
            start = end + 1;
            line
        })
}

/// Whether `line` is the `ip -o` link line of `netdev`, `2: ens6: <...>`,
/// or of a veth peer named `netdev`, `2: ens6@if3: <...>`. An address line
/// names the device without a colon, `2: ens6    inet ...`.
fn link_line(line: &str, netdev: &str) -> bool {
    let mut words = line.split_whitespace();
    words.next().is_some_and(priority)
        && words
            .next()
            .and_then(|name| name.strip_suffix(':'))
            .and_then(|name| name.split('@').next())
            == Some(netdev)
}

/// Splits the output of the IPv6 capture batch at `netdev`'s link line into
/// the earlier commands' output, that line, and the complete route listing
/// that follows it on a host with IPv6.
///
/// # Errors
///
/// `Unverifiable("ip")` when the output holds no link line of `netdev`.
fn split_link<'o>(output: &'o str, netdev: &str) -> Result<(&'o str, &'o str, &'o str), EniError> {
    let mut start = 0;
    for line in output.split_inclusive('\n') {
        if link_line(line, netdev) {
            let after = start + line.len();
            return Ok((&output[..start], line, &output[after..]));
        }
        start += line.len();
    }
    Err(EniError::Unverifiable("ip"))
}

/// What the kernel derives an address's local-table entries from.
struct Assigned {
    local: u32,
    /// The bits of an address below the prefix.
    host_bits: u32,
    /// The address's `brd`.
    broadcast: Option<Ipv4Addr>,
}

impl Assigned {
    /// Reads `captured`, an address specification as `address` returns it;
    /// `None` for one with no prefix length, an address that is no IPv4
    /// address or a prefix length that is no number. A prefix length of 32
    /// or more leaves no host bits.
    fn read(captured: &str) -> Option<Self> {
        let mut words = captured.split_whitespace();
        let (local, prefix) = words.next()?.split_once('/')?;
        let local = u32::from(local.parse::<Ipv4Addr>().ok()?);
        let host_bits = u32::MAX.checked_shr(prefix.parse().ok()?).unwrap_or(0);
        let broadcast = words.skip_while(|word| *word != "brd").nth(1);
        Some(Self {
            local,
            host_bits,
            broadcast: broadcast.and_then(|broadcast| broadcast.parse().ok()),
        })
    }

    /// The addresses the kernel derives a local-table `broadcast` entry
    /// for: the address's `brd`, unless that is 255.255.255.255 or
    /// 0.0.0.0, and, below a /31 prefix whose network lies outside
    /// 0.0.0.0/8, the last address of its prefix. A secondary address
    /// shares its primary's prefix, so it names the same last address.
    fn broadcasts(&self) -> impl Iterator<Item = u32> {
        let network = self.local & !self.host_bits;
        let last = (self.host_bits > 1 && network >> 24 != 0).then_some(network | self.host_bits);
        let brd = self.broadcast.map(u32::from);
        brd.filter(|brd| !matches!(*brd, 0 | u32::MAX))
            .into_iter()
            .chain(last)
    }
}

/// Whether `words` read as the kernel prints a local-table entry it derives
/// from one of `addresses`, the captured addresses in the kernel's order:
/// `local <address> table local proto kernel scope host src <primary>` for
/// the address itself, and `broadcast <entry> table local proto kernel
/// scope link src <primary>` for each of its
/// [`broadcasts`](Assigned::broadcasts). The primary is the first of
/// `addresses` with
/// the address's prefix length and network. It supplies `src` for every
/// address with that prefix length and network.
fn derived_entry(addresses: &[Assigned], words: &[&str]) -> bool {
    let [
        kind,
        entry,
        "table",
        "local",
        "proto",
        "kernel",
        "scope",
        scope,
        "src",
        src,
    ] = *words
    else {
        return false;
    };
    let (Ok(entry), Ok(src)) = (entry.parse::<Ipv4Addr>(), src.parse::<Ipv4Addr>()) else {
        return false;
    };
    addresses.iter().any(|address| {
        let network = address.local | address.host_bits;
        let derives = match (kind, scope) {
            ("local", "host") => u32::from(entry) == address.local,
            ("broadcast", "link") => address
                .broadcasts()
                .any(|derived| derived == u32::from(entry)),
            _ => false,
        };
        let primary = || {
            addresses.iter().find(|other| {
                other.host_bits == address.host_bits && other.local | other.host_bits == network
            })
        };
        derives && primary().is_some_and(|primary| primary.local == u32::from(src))
    })
}

/// Whether `word` is a decimal index or priority followed by a colon, as
/// `ip -o` leads an address or link line, `3:`, and a rule, `32765:`. A
/// route's first word is its destination, which for an IPv6 host route
/// such as `2001:db8::` also ends in a colon.
fn priority(word: &str) -> bool {
    word.strip_suffix(':')
        .is_some_and(|number| number.parse::<u32>().is_ok())
}

/// Checks the output of `ip IP_SHOW6` for `netdev`, whose one link-local
/// address is `link_local`, and returns the device's names: `netdev` and
/// every `altname` its link line lists. Each IPv6 route of the device must
/// read, apart from the `linkdown` and `dead` flags, exactly as the kernel
/// prints its own entry of that link-local address: the main table's
/// `fe80::/64 proto kernel metric 256 pref medium`, the local table's `local`
/// entry of the address at metric 0 and its `multicast ff00::/8` at metric
/// 256. A route a user labels `proto kernel` with a gateway, next hops or
/// another metric causes the check to fail, because the kernel regenerates
/// only its own entries when the device returns. The check also fails if an
/// IPv6 rule names the device by any of its names or its link-local address.
///
/// # Errors
///
/// `Unverifiable("ip")` for output without the device's link line,
/// `"routes"` for any other IPv6 route of the device, for a multipath route
/// of the complete listing with a next hop on the device and for a route
/// there that names no device, and `"rules"` for a rule naming the device
/// or its link-local address.
fn ipv6_state<'o>(
    output: &'o str,
    netdev: &'o str,
    link_local: Option<Ipv6Addr>,
) -> Result<Vec<&'o str>, EniError> {
    let (body, link, complete) = split_link(output, netdev)?;
    // The listing by device leaves out, before `ip` 6.10, a route that names the device only in a next hop
    // or a nexthop object. The bind removes such a route, which the complete listing shows as a multipath
    // route with a next hop on the device or as a route that names no device.
    for line in complete.lines().filter(|line| !line.trim().is_empty()) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let route = RouteWords::read(&words, false).ok_or(EniError::Unverifiable("routes"))?;
        if route.hops.contains(&netdev) || (route.device.is_none() && route.hops.is_empty()) {
            return Err(EniError::Unverifiable("routes"));
        }
    }
    let lines = body.lines().filter(|line| !line.trim().is_empty());
    // The link line reads `2: ens6: <...> ...\    altname eni0`.
    let link: Vec<&str> = link.split_whitespace().collect();
    let mut names = vec![netdev];
    names.extend(
        link.windows(2)
            .filter(|pair| pair[0] == "altname")
            .map(|pair| pair[1].trim_end_matches('\\')),
    );
    let mut rules = Vec::new();
    for line in lines {
        // Rules keep `dead` and `linkdown`, which can be device names; only
        // route lines print them as flags.
        if line.split_whitespace().next().is_some_and(priority) {
            rules.push(line);
            continue;
        }
        let words: Vec<&str> = line
            .split_whitespace()
            .filter(|word| !matches!(*word, "linkdown" | "dead"))
            .collect();
        let derived = match words[..] {
            [
                "fe80::/64",
                "proto",
                "kernel",
                "metric",
                "256",
                "pref",
                "medium",
            ] => link_local.is_some(),
            [
                "local",
                address,
                "table",
                "local",
                "proto",
                "kernel",
                "metric",
                "0",
                "pref",
                "medium",
            ] => address
                .parse()
                .ok()
                .is_some_and(|address| link_local == Some(address)),
            [
                "multicast",
                "ff00::/8",
                "table",
                "local",
                "proto",
                "kernel",
                "metric",
                "256",
                "pref",
                "medium",
            ] => true,
            _ => false,
        };
        if !derived {
            return Err(EniError::Unverifiable("routes"));
        }
    }
    let named = |word: &str| {
        names.contains(&word)
            || word
                .split('/')
                .next()
                .and_then(|word| word.parse().ok())
                .is_some_and(|address: Ipv6Addr| link_local == Some(address))
    };
    if rules
        .iter()
        .any(|rule| rule.split_whitespace().skip(1).any(named))
    {
        return Err(EniError::Unverifiable("rules"));
    }
    Ok(names)
}

/// Parses an `ip -4 -o addr` line of `netdev` into an address
/// specification for `ip addr replace`: the address and prefix, then `brd`,
/// `metric` and `noprefixroute` when the line has them. The kernel uses
/// `metric` for prefix-route priority and `noprefixroute` to suppress
/// automatic prefix-route creation. Replay assigns each address with a
/// forever lifetime, so the line's `secondary` and `dynamic` flags and its
/// lifetimes are dropped. The label is the last word before the line's
/// `\` continuation, or the line's last word. A line whose words exclude
/// `inet` returns `None`.
///
/// # Errors
///
/// `Unverifiable`, checked in this order: first the label, where any label
/// other than `netdev`, an alias such as `ens6:1` included, or a missing one
/// refuses (`"label"`); then the address, which refuses in 127.0.0.0/8
/// whatever scope it lists, because replay names no scope and `ip addr
/// replace` assigns such an address at scope host (`"scope"`); then each
/// word in turn, where a scope other than
/// `global` (`"scope"`), a `peer` (`"peer"`), `deprecated`
/// (`"deprecated"`), any other word, a `brd` whose value is an invalid IPv4
/// address or a `metric` whose value is an invalid `u32` (`"addresses"`)
/// refuses at its word; then a missing scope (`"scope"`).
fn address(line: &str, netdev: &str) -> Result<Option<String>, EniError> {
    let (head, lifetimes) = line.split_once('\\').unwrap_or((line, ""));
    // The words after `inet`: the address, its attributes and the label.
    let mut words = head.split_whitespace();
    if !words.any(|word| word == "inet") {
        return Ok(None);
    }
    if words.next_back() != Some(netdev) || words.clone().next().is_none() {
        return Err(EniError::Unverifiable("label"));
    }
    let malformed = || EniError::Unverifiable("addresses");
    let mut words = words.chain(lifetimes.split_whitespace());
    let mut address = String::with_capacity(line.len());
    address.push_str(words.next().ok_or_else(malformed)?);
    // Replay names no scope, and `ip addr replace` then assigns an address in 127.0.0.0/8 at scope host.
    let local = address.split('/').next().unwrap_or(&address);
    if local
        .parse()
        .is_ok_and(|local: Ipv4Addr| local.is_loopback())
    {
        return Err(EniError::Unverifiable("scope"));
    }
    let (mut broadcast, mut metric, mut no_prefix_route) = (None, None, false);
    let mut global = false;
    while let Some(word) = words.next() {
        match word {
            "brd" => {
                let value: Ipv4Addr = words
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(malformed)?;
                broadcast = Some(value);
            }
            "metric" => {
                let value: u32 = words
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(malformed)?;
                metric = Some(value);
            }
            "scope" => {
                if words.next() != Some("global") {
                    return Err(EniError::Unverifiable("scope"));
                }
                global = true;
            }
            "valid_lft" | "preferred_lft" => {
                words.next().ok_or_else(malformed)?;
            }
            "noprefixroute" => no_prefix_route = true,
            "secondary" | "dynamic" => {}
            "peer" => return Err(EniError::Unverifiable("peer")),
            "deprecated" => return Err(EniError::Unverifiable("deprecated")),
            _ => return Err(malformed()),
        }
    }
    if !global {
        return Err(EniError::Unverifiable("scope"));
    }
    if let Some(broadcast) = broadcast {
        let _ = write!(address, " brd {broadcast}");
    }
    if let Some(metric) = metric {
        let _ = write!(address, " metric {metric}");
    }
    if no_prefix_route {
        address += " noprefixroute";
    }
    Ok(Some(address))
}

/// The route types that name no device. `ip` lists a route of one by its
/// type, and `ip -batch` from 6.10 on under every device as well.
const DEVICE_LESS: [&str; 6] = [
    "blackhole",
    "unreachable",
    "prohibit",
    "throw",
    "nat",
    "xresolve",
];

/// The fields one listed IPv4 route holds for the capture and for release:
/// `ip route show` prints a route's type when it is not unicast, then its
/// destination, then its attributes, each a word or a word and its value.
struct RouteWords<'r> {
    /// The type word, such as `multicast`; a unicast route lists none.
    kind: Option<&'r str>,
    destination: &'r str,
    /// The route's own type of service, as listed, and its metric.
    tos: Option<&'r str>,
    metric: Option<&'r str>,
    /// The gateway `via` names, and whether it is an IPv6 address.
    gateway: Option<&'r str>,
    inet6: bool,
    onlink: bool,
    /// The listed scope; `ip` lists none for scope global.
    scope: Option<&'r str>,
    /// The listed table, where `None` is the main table.
    table: Option<&'r str>,
    /// `ip` prints `encap` options before the route's own attributes, so a
    /// read can mistake an encapsulation `tos` or a `seg6local` `table` for
    /// a route attribute.
    encap: bool,
    /// The preferred source address, `src`.
    source: Option<&'r str>,
    /// Whether the route goes through a nexthop object, `nhid N`, and the
    /// device a listing that is not by device names with `dev`.
    object: bool,
    device: Option<&'r str>,
    /// The device each next hop of a multipath route names.
    hops: Vec<&'r str>,
    /// The listed words of a strictly read route without the `linkdown` and
    /// `dead` state flags; empty for any other read.
    words: Vec<&'r str>,
}

/// The scope numbers the kernel orders routes by: a gateway is reached
/// through a route at `link` or `host`.
const LINK: u8 = 253;
const HOST: u8 = 254;

/// The smallest MTU at which the kernel holds IPv6 state for a device. On a
/// device below it the kernel refuses a route through an IPv6 gateway, and
/// keeps listing one added at a larger MTU.
const IPV6_MIN_MTU: u32 = 1280;

/// The number of a scope listed under one of `ip`'s own names or as a
/// number, and `None` for a name the host's `rt_scopes` gives.
fn scope_number(scope: &str) -> Option<u8> {
    match scope {
        "global" => Some(0),
        "site" => Some(200),
        "link" => Some(LINK),
        "host" => Some(HOST),
        "nowhere" => Some(255),
        number => number.parse().ok(),
    }
}

/// The network and prefix length of `prefix`, a destination or an address
/// with its prefix length as `ip` lists it; `None` for any other text.
fn network(prefix: &str) -> Option<(u32, u32)> {
    if prefix == "default" {
        return Some((0, 0));
    }
    let (address, length) = prefix.split_once('/').unwrap_or((prefix, "32"));
    let address = address.parse::<Ipv4Addr>().ok()?;
    let length = length.parse::<u32>().ok().filter(|length| *length <= 32)?;
    Some((u32::from(address) & mask(length), length))
}

/// The bits of an address that a prefix of `length` bits holds, for a
/// `length` of at most 32.
fn mask(length: u32) -> u32 {
    u32::MAX.checked_shl(32 - length).unwrap_or(0)
}

/// Whether the network and prefix length [`network`] returned hold
/// `address`.
fn holds((network, length): (u32, u32), address: u32) -> bool {
    address & mask(length) == network
}

impl<'r> RouteWords<'r> {
    /// Reads `listed`, the words of one listed route.
    ///
    /// The read takes the word after `proto`, `tos` and `congctl` as a
    /// value, whatever it spells, because `ip` lists those by the names the
    /// host's tables give. `linkdown` and `dead` where an attribute may
    /// stand are state flags, which the read leaves out of the words it
    /// keeps. It returns `None` for an attribute with no value and for a
    /// strictly read multipath route's `nexthop`.
    ///
    /// A `strict` read judges the words of a route of the device and keeps
    /// them for release, and [`replays_unchanged`](Self::replays_unchanged)
    /// judges its type, table and scope. It returns `None` for every word
    /// outside the attributes `ip route replace` takes back as the same
    /// route: a destination, a `via`
    /// gateway, `proto`, `scope` as `host`, `link`, `global`, `site`,
    /// `nowhere` or a number, `src`, `metric`, `tos`, `onlink`, `table`, a
    /// numeric `realm`, `realms` with both sides numeric and at most 255,
    /// the metrics `mtu`, `advmss`, `window`, `ssthresh`, `cwnd`,
    /// `initcwnd`, `initrwnd`, `reordering`, `hoplimit` and `congctl`, each
    /// with an optional `lock`, `quickack` and `fastopen_no_cookie` of `0`
    /// or `1`, and `features` of one feature word. `ip` lists the other
    /// attributes in words its parser refuses or reads as another value:
    /// `rto_min`, listed as `rto_min lock <time>` when locked, which the
    /// parser refuses, and replayed as a locked value when listed without
    /// `lock`; `rtt` and `rttvar`, listed rounded; an `encap` block, whose
    /// type of service lists in decimal and reads back in hexadecimal; the
    /// `offload`, `trap`, `rt_offload`, `rt_trap` and `rt_offload_failed`
    /// flags; a realm listed by name; a scope under a name the host gave
    /// it, whose number release cannot order by; a locked `quickack` or
    /// feature; and `nhid`, a nexthop object, which leaves with the device.
    ///
    /// A read that is not `strict` passes over a word it does not know, for
    /// a route recorded under an earlier admission rule and for a host
    /// route the capture records nothing of, and keeps what such a route
    /// lists beyond a route of the device: `encap`, `nhid`, `dev` and the
    /// `dev` of each `nexthop`.
    fn read(listed: &[&'r str], strict: bool) -> Option<Self> {
        let mut words = listed.iter();
        let kind = listed.first().copied().filter(|word| {
            matches!(*word, "multicast" | "local" | "broadcast" | "anycast")
                || DEVICE_LESS.contains(word)
        });
        if kind.is_some() {
            words.next();
        }
        let destination = *words.next()?;
        if strict && destination != "default" {
            let (address, prefix) = destination.split_once('/').unwrap_or((destination, "32"));
            address.parse::<Ipv4Addr>().ok()?;
            prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 32)?;
        }
        // A strict read keeps the route's words, at most the listed ones, in one allocation.
        let mut kept = Vec::new();
        if strict {
            kept.reserve_exact(listed.len());
            kept.extend_from_slice(&listed[..listed.len() - words.as_slice().len()]);
        }
        let mut route = Self {
            kind,
            destination,
            tos: None,
            metric: None,
            gateway: None,
            inet6: false,
            onlink: false,
            scope: None,
            table: None,
            encap: false,
            source: None,
            object: false,
            device: None,
            hops: Vec::new(),
            words: kept,
        };
        // Whether a `nexthop` has passed, so a `dev` names a next hop's device.
        let mut multipath = false;
        loop {
            let from = words.as_slice();
            let Some(&word) = words.next() else { break };
            match word {
                "linkdown" | "dead" => continue,
                "via" => {
                    let mut gateway = *words.next()?;
                    let known = if gateway == "inet6" {
                        route.inet6 = true;
                        gateway = *words.next()?;
                        !strict || gateway.parse::<Ipv6Addr>().is_ok()
                    } else {
                        !strict || gateway.parse::<Ipv4Addr>().is_ok()
                    };
                    if !known {
                        return None;
                    }
                    route.gateway = Some(gateway);
                }
                "proto" => {
                    words.next()?;
                }
                "scope" => {
                    let scope = *words.next()?;
                    if strict && scope_number(scope).is_none() {
                        return None;
                    }
                    route.scope = Some(scope);
                }
                "table" => route.table = Some(*words.next()?),
                "encap" if !strict => route.encap = true,
                "nhid" if !strict => {
                    words.next()?;
                    route.object = true;
                }
                "dev" if !strict && multipath => route.hops.push(*words.next()?),
                "dev" if !strict => route.device = Some(*words.next()?),
                "nexthop" if !strict => multipath = true,
                "nexthop" => return None,
                "src" => {
                    let source = *words.next()?;
                    if strict && source.parse::<Ipv4Addr>().is_err() {
                        return None;
                    }
                    route.source = Some(source);
                }
                "metric" => {
                    let metric = *words.next()?;
                    if strict && metric.parse::<u32>().is_err() {
                        return None;
                    }
                    route.metric = Some(metric);
                }
                "tos" => route.tos = Some(*words.next()?),
                "onlink" => route.onlink = true,
                "realm" => {
                    let realm = *words.next()?;
                    if strict && realm.parse::<u32>().is_err() {
                        return None;
                    }
                }
                "realms" => {
                    let realms = *words.next()?;
                    let sides = realms.split_once('/');
                    let small = |side: &str| side.parse::<u32>().is_ok_and(|realm| realm <= 255);
                    if strict && !sides.is_some_and(|(from, to)| small(from) && small(to)) {
                        return None;
                    }
                }
                "mtu" | "advmss" | "window" | "ssthresh" | "cwnd" | "initcwnd" | "initrwnd"
                | "reordering" | "hoplimit" | "congctl" => {
                    if words.as_slice().first() == Some(&"lock") {
                        words.next();
                    }
                    let value = *words.next()?;
                    if strict && word != "congctl" && value.parse::<u32>().is_err() {
                        return None;
                    }
                }
                "quickack" | "fastopen_no_cookie" => {
                    let value = *words.next()?;
                    if strict && !matches!(value, "0" | "1") {
                        return None;
                    }
                }
                "features" => {
                    let feature = *words.next()?;
                    if strict && !matches!(feature, "ecn" | "tcp_usec_ts") {
                        return None;
                    }
                }
                _ if strict => return None,
                _ => {}
            }
            if strict {
                route
                    .words
                    .extend_from_slice(&from[..from.len() - words.as_slice().len()]);
            }
        }
        Some(route)
    }

    /// Whether `ip route replace` of this strictly read main-table route's
    /// words writes the same route to the main table. `ip` writes a `local`,
    /// `broadcast` or `anycast` route without a table word to table local.
    /// It lists no scope for a route at scope global, and without a scope
    /// word writes a route with no gateway, and a multicast route, at scope
    /// link. It reads a `default` destination through an IPv6 gateway as an
    /// IPv6 route.
    fn replays_unchanged(&self) -> bool {
        let multicast = match self.kind {
            None => false,
            Some("multicast") => true,
            Some(_) => return false,
        };
        (self.scope.is_some() || (self.gateway.is_some() && !multicast))
            && !(self.inet6 && self.destination == "default")
    }

    /// The group release replays this route in: 0 for a host-scope route, 1
    /// for a link-scope route and every other route with no gateway, 2 for
    /// the rest.
    fn order(&self) -> u8 {
        match self.scope.and_then(scope_number) {
            Some(HOST) => 0,
            Some(LINK) => 1,
            _ if self.gateway.is_none() => 1,
            _ => 2,
        }
    }

    /// The key under which the kernel's `ip route replace` finds an
    /// existing main-table IPv4 route: its destination, type of service and
    /// metric, not its gateway or its type. `ip route append` leaves two
    /// routes under one key, which list as two lines; a replace of the
    /// second overwrites the first.
    fn key(&self) -> (&'r str, Option<&'r str>, Option<&'r str>) {
        (self.destination, self.tos, self.metric)
    }

    /// Whether a main-table `route replace` under `key` can write over this
    /// listed route. A route with an `encap` block matches under any type
    /// of service and table, because the block's options can stand in for
    /// the route's own `tos` and `table` in the listing.
    fn replaced_under(
        &self,
        (destination, tos, metric): (&str, Option<&str>, Option<&str>),
    ) -> bool {
        self.destination == destination
            && self.metric == metric
            && (self.encap || (self.table.is_none() && self.tos == tos))
    }
}

/// What release's replay gives the kernel to reach gateways through, from a
/// capture's addresses and admitted routes.
///
/// The kernel looks a gateway up through the policy rules in their listed
/// order, with no source address, the gateway as destination and no mark,
/// and each rule that matches reads its table or ends the lookup. A rule
/// with a `from` prefix that does not hold 0.0.0.0, or a `to` prefix that
/// does not hold the gateway, does not match; a rule with `not`, and a rule
/// with any other selector, counts as matching every gateway, since the
/// capture reads no other selector.
///
/// The kernel takes a gateway that is one of the device's addresses at the
/// rule `from all lookup local`, or `from all to <prefix> lookup local` with
/// a prefix that holds it, unless an entry of the local table stands
/// before the address's own under that one address at metric 0 and an
/// adequate scope, since the lookup returns the earlier entry: a
/// device-less route that stays through the bind, after which release
/// assigns the address, or the `broadcast` entry of an address listed
/// earlier, which release assigns first. For any other gateway a rule that
/// reads the local table refuses it when that table holds, at a scope
/// nearer than the gateway route's and at least `link`, a `broadcast` entry
/// the kernel derives from the device's addresses at the gateway, or a
/// device-less route with no type of service over it. Such a route refuses
/// the gateway whatever its prefix length: on a host that has held no
/// policy rule the lookup reads the local and main tables as one, and on
/// any other it reads the local table first. At the rule
/// `from all lookup main` the lookup reads the main table's entries with no
/// type of service at that scope: the device's routes, and the host's
/// routes of a device-less type, which the lookup returns whatever device
/// it names. Of those that hold the gateway, the entry with the longest
/// prefix decides, and of several with that prefix the one with the lowest
/// metric. The kernel takes the gateway when that entry is a unicast route
/// and refuses it for any other, a multicast route or a device-less route,
/// whatever unicast route holds the gateway at a shorter prefix or a higher
/// metric.
///
/// A matching rule listed before `from all lookup main` refuses the gateway
/// when its action is anything but a table lookup, such as `prohibit` or
/// `goto`, and when the table it reads holds a device-less route other than
/// `throw` over the gateway at that scope, whatever its prefix length. A
/// rule `from all to <prefix> lookup main` decides as `from all lookup main`
/// does for the gateways its prefix holds. Any other rule that reads the
/// main table refuses the gateway when the entry its lookup returns is no
/// unicast route, and otherwise leaves the lookup to the rules after it,
/// since the capture does not read what makes it match or pass. A
/// listing in which no rule reaches the gateway's entry refuses the gateway:
/// for a gateway that is no address of the device, one with no rule
/// `from all lookup main` and no rule `from all to <prefix> lookup main`
/// whose prefix holds the gateway, and for every gateway, one with no rule
/// at all. A `nop` rule passes the lookup on, and a rule's `proto` and
/// `realms` words change no lookup.
///
/// Release assigns the addresses in order, and the kernel adds a link-scope
/// prefix route with the first address of each network and prefix length
/// unless that address holds `noprefixroute` or the network lies in
/// 0.0.0.0/8. Release then replays the routes in their
/// [`order`](RouteWords::order) groups, each group in listed order, and each
/// replay writes over the route of the same network, prefix length, type of
/// service and metric. A prefix route therefore stands at a gateway route's
/// replay when every route of its network and prefix length, with the
/// default type of service and its address's metric, is the gateway's own
/// route or is replayed after it. A listed route at scope `link` or `host`
/// is replayed in an earlier group than every gateway route whose lookup
/// takes that scope, so it stands at each of their replays. A gateway route
/// stays listed after the address or route that reached it is removed, and
/// the kernel refuses its replay.
struct Reach {
    /// The device's addresses, ascending.
    locals: Vec<u32>,
    /// The main-table entries a gateway's lookup can return, ascending: the
    /// prefix routes the kernel derives from the addresses, each listed
    /// route with no type of service at scope `link` or nearer, and each
    /// such host route of a device-less type.
    near: Vec<Near>,
    /// The addresses the kernel derives a local-table `broadcast` entry
    /// for, ascending.
    broadcasts: Vec<u32>,
    /// Each host route of a device-less type in the local table with no type
    /// of service at scope `link` or nearer.
    local_rejects: Vec<Near>,
    /// Each prefix length of `near`, once, longest first.
    lengths: Vec<u32>,
    /// The device's addresses that an earlier listed address derives a
    /// `broadcast` entry for, ascending. Release assigns the addresses in
    /// listed order, so that entry stands before the address's own.
    shadowed: Vec<u32>,
    /// The `to` prefix and the action of each rule that may match a
    /// gateway's lookup, in listed order through the first rule
    /// `from all lookup main`.
    rules: Vec<((u32, u32), Step)>,
}

/// What a policy rule does to a gateway's lookup that it matches.
enum Step {
    /// A lookup of the local table: a device-less route of that table over
    /// the gateway refuses it, and a rule that holds `from all`, a `to`
    /// prefix at most and no other word, marked `true`, takes a gateway
    /// that is one of the device's addresses.
    Local(bool),
    /// A lookup of the main table. Under a rule that holds `from all`, a
    /// `to` prefix at most and no other word, marked `true`, the entry of
    /// `near` the lookup returns decides. Under any other rule an entry
    /// that is no unicast route refuses the gateway, and a unicast one
    /// leaves the lookup to the rules that follow.
    Main(bool),
    /// An action other than a table lookup, which ends the lookup.
    Ends,
    /// A lookup of another table, with that table's device-less routes
    /// other than `throw` with no type of service at scope `link` or nearer.
    Table(Vec<Near>),
}

/// An entry a gateway's lookup can return. The order of the fields sorts the
/// entries of one network and prefix length as the lookup reads them: by
/// rising metric, and under one metric an entry that is no unicast route
/// first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Near {
    length: u32,
    network: u32,
    metric: u32,
    /// Whether the entry is a unicast route, through which the kernel takes
    /// a gateway. A multicast route and a device-less route are the other
    /// entries.
    unicast: bool,
    scope: u8,
    /// For a prefix route the kernel derives from an address, the order
    /// group and listed place of the first route release replays under its
    /// key, which writes over it.
    replaced: Option<(u8, usize)>,
}

impl Reach {
    /// Reads `addresses`, `routes`, `host_routes` and `rules`, the lines of
    /// the IPv4 rule listing, `routes` and `rules` in listed order.
    fn of(
        routes: &[RouteWords],
        addresses: &[String],
        host_routes: &[RouteWords],
        rules: &[&str],
    ) -> Self {
        let mut reach = Self {
            locals: Vec::new(),
            near: Vec::new(),
            broadcasts: Vec::new(),
            local_rejects: Vec::new(),
            lengths: Vec::new(),
            shadowed: Vec::new(),
            rules: Vec::new(),
        };
        // The listed prefix length and the network of each address that is the first of its network and
        // prefix length.
        let mut primaries: Vec<(Option<&str>, (u32, u32))> = Vec::new();
        for address in addresses {
            let mut words = address.split(' ');
            let prefix = words.next().unwrap_or_default();
            let (local, length) = match prefix.split_once('/') {
                Some((local, length)) => (local, Some(length)),
                None => (prefix, None),
            };
            let local = local.parse::<Ipv4Addr>().ok().map(u32::from);
            // The entries of the addresses read so far stand before this address's own.
            let first =
                |local: &u32| reach.broadcasts.contains(local) && !reach.locals.contains(local);
            reach.shadowed.extend(local.filter(first));
            reach.locals.extend(local);
            if let Some(assigned) = Assigned::read(address) {
                reach.broadcasts.extend(assigned.broadcasts());
            }
            let Some(network) = network(prefix) else {
                continue;
            };
            // An address after another of its network and prefix length is a secondary, which brings no prefix route.
            let secondary = |local| {
                primaries
                    .iter()
                    .any(|(listed, primary)| *listed == length && holds(*primary, local))
            };
            if local.is_some_and(secondary) {
                continue;
            }
            primaries.push((length, network));
            // A network in 0.0.0.0/8 gets no prefix route, and neither does a /32 address. The prefix has
            // such a network when it holds the address with its first octet cleared.
            let zero_network = local.is_some_and(|local| holds(network, local & 0x00ff_ffff));
            let alone = zero_network || network.1 == 32;
            if alone || words.clone().any(|word| word == "noprefixroute") {
                continue;
            }
            // The metric an address gives its prefix route; an address lists none at zero.
            let metric = words
                .skip_while(|word| *word != "metric")
                .nth(1)
                .map_or(Some(0), |metric| metric.parse().ok());
            let Some(metric) = metric else {
                continue;
            };
            reach.near.push(Near {
                length: network.1,
                network: network.0,
                metric,
                unicast: true,
                scope: LINK,
                replaced: None,
            });
        }
        reach.locals.sort_unstable();
        reach.shadowed.sort_unstable();
        reach.broadcasts.sort_unstable();
        let derived = reach.near.len();
        for (place, route) in routes.iter().enumerate() {
            if route.tos.is_some() {
                continue;
            }
            let Some((network, length)) = network(route.destination) else {
                continue;
            };
            let Some(metric) = route.metric.map_or(Some(0), |metric| metric.parse().ok()) else {
                continue;
            };
            let at = (route.order(), place);
            for prefix in &mut reach.near[..derived] {
                if (prefix.network, prefix.length, prefix.metric) == (network, length, metric)
                    && prefix.replaced.is_none_or(|first| at < first)
                {
                    prefix.replaced = Some(at);
                }
            }
            let scope = route.scope.and_then(scope_number);
            if let Some(scope) = scope.filter(|scope| *scope >= LINK) {
                reach.near.push(Near {
                    length,
                    network,
                    metric,
                    unicast: route.kind.is_none(),
                    scope,
                    replaced: None,
                });
            }
        }
        // No replayed route writes over a host route, so these entries stand at every replay.
        let hides = |network, scope| Near {
            length: 32,
            network,
            metric: 0,
            unicast: false,
            scope,
            replaced: None,
        };
        // The device-less routes of each table but local and main, under the table's listed word.
        let mut tables: Vec<(&str, Near)> = Vec::new();
        for host in host_routes {
            // A scope under a name the host gave counts as the nearest. A route with an `encap` block
            // lists the block's `tos` and counts whatever it lists.
            let scope = host
                .scope
                .map_or(0, |scope| scope_number(scope).unwrap_or(u8::MAX));
            let device_less = host.kind.is_some_and(|kind| DEVICE_LESS.contains(&kind));
            if !device_less || scope < LINK || !(host.encap || host.tos.is_none()) {
                continue;
            }
            let Some((network, length)) = network(host.destination) else {
                continue;
            };
            let metric = host.metric.and_then(|metric| metric.parse().ok());
            let reject = Near {
                length,
                metric: metric.unwrap_or(0),
                ..hides(network, scope)
            };
            match host.table {
                Some("local" | "255") => reach.local_rejects.push(reject),
                None => reach.near.push(reject),
                Some(table) => {
                    // The words of an `encap` block may stand in for the route's own table, so such a
                    // route counts in the main table and in the table it lists.
                    if host.encap {
                        reach.near.push(reject);
                    }
                    if host.kind != Some("throw") {
                        tables.push((table, reject));
                    }
                }
            }
        }
        reach.near.sort_unstable();
        reach.lengths = reach.near.iter().rev().map(|near| near.length).collect();
        reach.lengths.dedup();
        for rule in rules {
            // `ip` lists a rule as its priority, `not`, `from` and its prefix, `to` and its prefix,
            // its other selectors, its action, and `proto` with the rule's origin.
            // `ip` ends a word at ASCII whitespace alone, so a name that holds another space is one word.
            let mut words: Vec<&str> = rule.split_ascii_whitespace().skip(1).collect();
            // The rule's origin and the realms it assigns change no lookup.
            for tag in ["proto", "realms"] {
                if matches!(words[..], [.., word, _] if word == tag) {
                    words.truncate(words.len() - 2);
                }
            }
            let plain = match words[..] {
                ["from", "all", "lookup", table] => Some(table),
                _ => None,
            };
            if matches!(plain, Some("main" | "254")) {
                reach.rules.push(((0, 0), Step::Main(true)));
                break;
            }
            // Whether the rule matches every lookup of a gateway its `to` prefix holds.
            let sure = match words[..] {
                ["from", "all", "to", to, "lookup", _] => network(to).is_some(),
                _ => false,
            };
            let not = words.first() == Some(&"not");
            let selectors = &words[usize::from(not)..];
            let (from, to) = match *selectors {
                ["from", from, "to", to, ..] => (from, Some(to)),
                ["from", from, ..] => (from, None),
                _ => ("all", None),
            };
            // A prefix the capture cannot read counts as one that holds every address.
            let prefix = |word: &str| network(word).unwrap_or((0, 0));
            if !not && from != "all" && prefix(from).0 != 0 {
                continue;
            }
            let to = to.filter(|_| !not).map_or((0, 0), prefix);
            while let [.., "suppress_prefixlength" | "suppress_ifgroup", _] = words[..] {
                words.truncate(words.len() - 2);
            }
            let step = match words[..] {
                [.., "iif" | "oif", "lookup", _] => Step::Ends,
                [.., "lookup", "local" | "255"] => Step::Local(plain.is_some() || sure),
                [.., "lookup", "main" | "254"] => Step::Main(sure),
                [.., "lookup", table] => Step::Table(
                    tables
                        .iter()
                        .filter(|(listed, _)| *listed == table)
                        .map(|(_, reject)| *reject)
                        .collect(),
                ),
                [.., "nop"] => continue,
                _ => Step::Ends,
            };
            reach.rules.push((to, step));
        }
        reach
    }

    /// Whether the replay gives the kernel a route to the gateway of
    /// `route`, the route listed at `place`. A route with `onlink` needs no
    /// route to its gateway, and an IPv6 gateway counts as reached when it
    /// is link-local.
    fn reaches_gateway(&self, route: &RouteWords, place: usize) -> bool {
        let Some(gateway) = route.gateway else {
            return true;
        };
        if route.onlink {
            return true;
        }
        if route.inet6 {
            return gateway
                .parse::<Ipv6Addr>()
                .is_ok_and(|gateway| gateway.is_unicast_link_local());
        }
        let scope = route.scope.map_or(Some(0), scope_number);
        let (Ok(gateway), Some(scope)) = (gateway.parse::<Ipv4Addr>(), scope) else {
            return false;
        };
        let gateway = u32::from(gateway);
        let nearer = scope.saturating_add(1).max(LINK);
        let own = nearer <= HOST && self.locals.binary_search(&gateway).is_ok();
        // Release assigns an address after a device-less route that stays under that address and metric 0,
        // and the lookup returns the earlier entry of the two. Any other entry stands after the address's own.
        let rejected = |reject: &Near| {
            reject.scope >= nearer
                && holds((reject.network, reject.length), gateway)
                && (!own || (reject.length, reject.metric) == (32, 0))
        };
        // A lookup at scope `link` returns a `broadcast` entry at the gateway: for a gateway that is no
        // address of the device any such entry, and for one that is, the entry of an earlier address.
        let entries = if own {
            &self.shadowed
        } else {
            &self.broadcasts
        };
        let behind = nearer == LINK && entries.binary_search(&gateway).is_ok();
        // A prefix route stands at this route's replay when no route under its key is replayed first.
        let at = (route.order(), place);
        let stands =
            |near: &&Near| near.scope >= nearer && near.replaced.is_none_or(|first| first >= at);
        // The first route that stands under the longest prefix holding the gateway is the one the lookup returns.
        let found = || {
            self.lengths.iter().find_map(|&length| {
                let network = (length, gateway & mask(length));
                let start = self
                    .near
                    .partition_point(|near| (near.length, near.network) < network);
                self.near[start..]
                    .iter()
                    .take_while(|near| (near.length, near.network) == network)
                    .find(stands)
            })
        };
        let over = |reject: &Near| {
            reject.scope >= nearer && holds((reject.network, reject.length), gateway)
        };
        // Each rule that may match reads its table or ends the lookup, in listed order.
        for (to, step) in &self.rules {
            if !holds(*to, gateway) {
                continue;
            }
            match step {
                Step::Local(_) if self.local_rejects.iter().any(rejected) || behind => {
                    return false;
                }
                Step::Local(plain) if *plain && own => return true,
                Step::Local(_) => {}
                Step::Main(sure) => match found() {
                    Some(near) if *sure || !near.unicast => return near.unicast,
                    _ => {}
                },
                Step::Ends => return false,
                Step::Table(rejects) if rejects.iter().any(over) => return false,
                Step::Table(_) => {}
            }
        }
        false
    }
}

/// The order release replays a recorded route in. The kernel resolves a
/// gateway through a route of a nearer scope, so host-scope routes come
/// first, then link-scope routes and every other route with no gateway,
/// then the rest. A record lists a scope as `host` or `link`, or as its
/// number.
pub(crate) fn replay_order(route: &str) -> u8 {
    let words: Vec<&str> = route.split_whitespace().collect();
    RouteWords::read(&words, false).map_or(2, |route| route.order())
}

/// Whether `text` is an ENI ID: `eni-` followed by hexadecimal digits, the
/// grammar ENI resolution requires.
pub fn is_eni_id(text: &str) -> bool {
    text.strip_prefix("eni-")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}
