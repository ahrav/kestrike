//! ENI network states carried from the capture through the record to
//! release.
//!
//! Each test puts addresses and routes on the fixture's ENI as `ip` lists
//! them, binds, and either reads the release batch back or requires the
//! refusal. A state release cannot restore must refuse the bind before any
//! driver write and leave no record. The listings of kernel states are the
//! forms iproute2 6.10 prints on Linux 6.12; a line with a missing or
//! malformed value is written by hand. The fixture's kernel takes every
//! command, so an admitted case checks the words release replays, and the
//! namespace cases of `network_tests` check that a kernel takes them.

use std::net::Ipv4Addr;

use super::binder::{BindError, mappings_path};
use super::binder_tests::{bind_eni, new_binder, untouched};
use super::eni::EniError;
use super::fixture::{FakeKernel, FakeMetadata, Fixture};
use super::mappings::Mappings;

const ADDRESSES: &str = "ip -4 -o addr show dev ens6";

const ROUTES: &str = "ip -4 -o route show table all dev ens6";

const HOST_ROUTES: &str = "ip -4 -o route show table all";

/// One IPv4 address of the device, with the attributes `ip addr replace`
/// takes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Address {
    local: Ipv4Addr,
    prefix: u8,
    broadcast: Option<Ipv4Addr>,
    metric: Option<u32>,
    no_prefix_route: bool,
}

/// One state: what the device holds before the bind, on the fixture's link,
/// which is up at MTU 9001.
#[derive(Debug, Clone)]
struct State {
    /// The addresses and routes [`expected`] compares a release with; a
    /// test that reads the release batch itself leaves both empty.
    addresses: Vec<Address>,
    /// Each route's words as `ip route replace` takes them.
    routes: Vec<Vec<String>>,
    /// The route lines as `ip -4 -o route show` prints them.
    route_lines: String,
}

impl State {
    /// A state of `route_lines` alone.
    fn listed(route_lines: impl Into<String>) -> Self {
        Self {
            addresses: Vec::new(),
            routes: Vec::new(),
            route_lines: route_lines.into(),
        }
    }
}

/// Puts `state` and `address_lines` on the fixture's ENI, as `ip` lists them.
fn install(kernel: &FakeKernel, state: &State, address_lines: String) {
    let mut outputs = kernel.outputs.borrow_mut();
    outputs.insert(ADDRESSES.to_owned(), Some(address_lines));
    outputs.insert(ROUTES.to_owned(), Some(state.route_lines.clone()));
}

/// What a release batch restores, read back from its `ip` command lines.
#[derive(Debug, Default, PartialEq, Eq)]
struct Replayed {
    /// The MTU and link commands in batch order.
    link: Vec<String>,
    addresses: Vec<Address>,
    routes: Vec<Vec<String>>,
}

/// Parses each command of a release batch on `ens6`.
///
/// # Panics
///
/// On a command that is no link, address or route command of `ens6`, or an
/// address word other than `brd`, `metric` and `noprefixroute`.
fn replayed(runs: &[String]) -> Replayed {
    let mut out = Replayed::default();
    for run in runs {
        let words: Vec<&str> = run.split(' ').collect();
        match words[..] {
            ["ip", "link", "set", "dev", "if6", ref rest @ ..] => out.link.push(rest.join(" ")),
            [
                "ip",
                "addr",
                "replace",
                address,
                ref rest @ ..,
                "dev",
                "if6",
            ] => {
                // `ip` reads an address without a prefix as a host address.
                let (local, prefix) = address.split_once('/').unwrap_or((address, "32"));
                let mut parsed = Address {
                    local: local.parse().unwrap(),
                    prefix: prefix.parse().unwrap(),
                    broadcast: None,
                    metric: None,
                    no_prefix_route: false,
                };
                let mut rest = rest.iter();
                while let Some(word) = rest.next() {
                    match *word {
                        "brd" => parsed.broadcast = Some(rest.next().unwrap().parse().unwrap()),
                        "metric" => parsed.metric = Some(rest.next().unwrap().parse().unwrap()),
                        "noprefixroute" => parsed.no_prefix_route = true,
                        other => panic!("{run}: address word {other}"),
                    }
                }
                out.addresses.push(parsed);
            }
            ["ip", "route", "replace", ref rest @ .., "dev", "if6"] => {
                out.routes
                    .push(rest.iter().map(|word| (*word).to_owned()).collect());
            }
            // Release reads the device's index first and names the device by it.
            ["ip", "-o", "link", "show"] => {}
            _ => panic!("a release command outside the ENI's network state: {run}"),
        }
    }
    out
}

/// The state release must restore: the fixture's link state, and `state`'s
/// addresses and routes.
fn expected(state: &State) -> Replayed {
    let mut addresses = state.addresses.clone();
    addresses.sort();
    let mut routes = state.routes.clone();
    routes.sort();
    Replayed {
        link: vec!["mtu 9001".to_owned(), "up".to_owned()],
        addresses,
        routes,
    }
}

/// Binds the fixture's ENI over `state`, reads the record back and releases;
/// returns what the release batch restores, addresses and routes sorted.
fn round_trip(state: &State, address_lines: String) -> Result<Replayed, BindError> {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    install(&binder.kernel, state, address_lines);
    let bound = match bind_eni(&binder, None, &FakeMetadata::new()) {
        Ok(bound) => bound,
        Err(error) => {
            assert!(untouched(&binder), "a refused bind wrote: {error:?}");
            assert!(!mappings_path(&fixture.state_dir()).exists());
            return Err(error);
        }
    };
    let read = Mappings::read(&mappings_path(&fixture.state_dir())).expect("the record reads");
    assert_eq!(read, bound, "the record reads back as written");
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).expect("the release");
    let mut replayed = replayed(&binder.kernel.runs.borrow());
    replayed.addresses.sort();
    replayed.routes.sort();
    Ok(replayed)
}

/// The fixture's own state, one address and one route, round-trips.
#[test]
fn the_fixed_eni_state_round_trips_through_the_record_to_release() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let bound = bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let read = Mappings::read(&mappings_path(&fixture.state_dir())).unwrap();
    assert_eq!(read, bound);
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    let address = Address {
        local: Ipv4Addr::new(10, 0, 1, 5),
        prefix: 24,
        broadcast: Some(Ipv4Addr::new(10, 0, 1, 255)),
        metric: Some(1003),
        no_prefix_route: false,
    };
    let route = "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003";
    assert_eq!(
        replayed(&binder.kernel.runs.borrow()),
        Replayed {
            link: vec!["mtu 9001".to_owned(), "up".to_owned()],
            addresses: vec![address],
            routes: vec![route.split(' ').map(str::to_owned).collect()],
        }
    );
}

/// A second address carrying an attribute the release batch has no word
/// for refuses the bind before any driver write: a peer, a scope other than
/// global, a label other than the device's name, or a deprecated address
/// would come back from release as a plain global address.
#[test]
fn an_address_release_cannot_restore_refuses_the_bind() {
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    let mut admitted = Vec::new();
    for unrestorable in [
        "3: ens6    inet 10.0.20.1 peer 10.0.20.2/32 scope global ens6\\       valid_lft forever preferred_lft forever\n",
        "3: ens6    inet 10.0.20.1/24 brd 10.0.20.255 scope link ens6\\       valid_lft forever preferred_lft forever\n",
        "3: ens6    inet 10.0.20.1/24 brd 10.0.20.255 scope host ens6\\       valid_lft forever preferred_lft forever\n",
        "3: ens6    inet 10.0.20.1/24 brd 10.0.20.255 scope global ens6:1\\       valid_lft forever preferred_lft forever\n",
        "3: ens6    inet 10.0.20.1/24 brd 10.0.20.255 scope global deprecated dynamic ens6\\       valid_lft 300sec preferred_lft 0sec\n",
    ] {
        let state = State::listed("10.0.1.0/24 proto kernel scope link src 10.0.1.5\n");
        let outcome = round_trip(&state, format!("{primary}{unrestorable}"));
        if !matches!(outcome, Err(BindError::Eni(EniError::Unverifiable(_)))) {
            admitted.push(format!(
                "{unrestorable:?} was admitted and released as {outcome:?}"
            ));
        }
    }
    assert!(admitted.is_empty(), "{}", admitted.join("\n"));
}

/// A route whose metric `ip` lists in words it takes back binds, and release
/// replays the words as listed: a locked MTU prints `mtu lock 1400`, which
/// `ip route replace` accepts.
#[test]
fn a_route_with_a_locked_mtu_round_trips_through_the_record_to_release() {
    let main = [
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5",
        "10.9.0.0/16 via 10.0.1.1 mtu lock 1400",
    ];
    let state = State {
        addresses: vec![Address {
            local: Ipv4Addr::new(10, 0, 1, 5),
            prefix: 24,
            broadcast: None,
            metric: None,
            no_prefix_route: false,
        }],
        routes: main
            .iter()
            .map(|route| route.split(' ').map(str::to_owned).collect())
            .collect(),
        route_lines: format!("{}\n{}\n", main[0], main[1]),
    };
    let primary = "3: ens6    inet 10.0.1.5/24 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    let replayed = round_trip(&state, primary.to_owned()).unwrap();
    assert_eq!(replayed, expected(&state));
}

/// A route through a nexthop object refuses the bind before any driver
/// write. The kernel deletes the object with the device when the ENI leaves
/// `ena`, and refuses an `ip route replace` that names `nhid` beside `via`,
/// so release could never restore the route, and the routes after it in the
/// batch, and would keep failing with the record in place.
#[test]
fn a_route_through_a_nexthop_object_refuses_the_bind() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let state = State::listed(
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                      10.9.0.0/16 nhid 7 via 10.0.1.1\n\
                      10.8.0.0/16 via 10.0.1.1 proto static\n",
    );
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    install(&binder.kernel, &state, primary.to_owned());
    // The kernel refuses this replay once the device returned to `ena`.
    binder.kernel.outputs.borrow_mut().insert(
        "ip route replace 10.9.0.0/16 nhid 7 via 10.0.1.1 dev if6".to_owned(),
        None,
    );
    let record = mappings_path(&fixture.state_dir());
    match bind_eni(&binder, None, &FakeMetadata::new()) {
        Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
            assert!(untouched(&binder), "the refused bind wrote");
            assert!(!record.exists(), "the refused bind left a record");
        }
        bound => {
            let first = binder.release(&[]);
            let second = binder.release(&[]);
            panic!(
                "the bind returned {bound:?}; release returned {first:?}, then {second:?}; \
                 the record exists afterward: {}",
                record.exists()
            );
        }
    }
}

/// A route through a nexthop object refuses the bind when `ip` lists it
/// without the object's next hop, as it does for every such route once
/// `net.ipv4.nexthop_compat_mode` is 0, a single object and a group alike.
/// No `via` or `nexthop` word marks the line, and release's replace, which
/// names the device beside `nhid`, fails at the kernel.
#[test]
fn a_route_listed_with_its_nexthop_id_alone_refuses_the_bind() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let state = State::listed(
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                      10.9.0.0/16 nhid 9\n\
                      10.8.0.0/16 via 10.0.1.1 proto static\n",
    );
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    install(&binder.kernel, &state, primary.to_owned());
    // The kernel refuses a device beside a nexthop ID.
    binder.kernel.outputs.borrow_mut().insert(
        "ip route replace 10.9.0.0/16 nhid 9 dev if6".to_owned(),
        None,
    );
    let record = mappings_path(&fixture.state_dir());
    match bind_eni(&binder, None, &FakeMetadata::new()) {
        Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
            assert!(untouched(&binder), "the refused bind wrote");
            assert!(!record.exists(), "the refused bind left a record");
        }
        bound => {
            let first = binder.release(&[]);
            panic!(
                "the bind returned {bound:?}; release returned {first:?}; \
                 the record exists afterward: {}",
                record.exists()
            );
        }
    }
}

const PRIMARY: &str = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";

const PREFIX_ROUTE: &str = "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n";

/// A main-table unicast route with a scope word binds, and release replays
/// its words unchanged: `ip route replace` writes a unicast route to main.
#[test]
fn a_main_table_unicast_route_with_a_scope_binds_and_replays_unchanged() {
    let state = State::listed(format!("{PREFIX_ROUTE}10.5.5.5 scope host\n"));
    let replayed = round_trip(&state, PRIMARY.to_owned()).expect("the unicast route binds");
    let words = |text: &str| -> Vec<String> { text.split(' ').map(str::to_owned).collect() };
    assert_eq!(
        replayed.routes,
        vec![
            words("10.0.1.0/24 proto kernel scope link src 10.0.1.5"),
            words("10.5.5.5 scope host"),
        ]
    );
}

/// A main-table route of type `multicast` binds, and release replays its
/// words unchanged: `ip route replace` writes a route of that type to main,
/// as it does a unicast one. The listing is the kernel's for
/// `ip route add multicast 239.1.0.0/16 dev ens6`.
#[test]
fn a_main_table_multicast_route_binds_and_replays_unchanged() {
    let state = State::listed(format!(
        "{PREFIX_ROUTE}multicast 239.1.0.0/16 scope link \n"
    ));
    let replayed = round_trip(&state, PRIMARY.to_owned()).expect("the multicast route binds");
    let words = |text: &str| -> Vec<String> { text.split(' ').map(str::to_owned).collect() };
    assert_eq!(
        replayed.routes,
        vec![
            words("10.0.1.0/24 proto kernel scope link src 10.0.1.5"),
            words("multicast 239.1.0.0/16 scope link"),
        ]
    );
}

/// Binds the fixture's ENI over `route_lines` and `address_lines`. A refused
/// bind must have written nothing and returns `None`; an admitted one
/// releases and returns the release batch's commands in order.
fn released_batch(address_lines: &str, route_lines: &str) -> Option<Vec<String>> {
    released_beside(address_lines, route_lines, "")
}

/// As [`released_batch`], on a host whose complete route listing holds
/// `host_lines`: the routes of other devices and of no device, each as `ip`
/// lists it outside a listing by device.
fn released_beside(
    address_lines: &str,
    route_lines: &str,
    host_lines: &str,
) -> Option<Vec<String>> {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let state = State::listed(route_lines);
    install(&binder.kernel, &state, address_lines.to_owned());
    binder
        .kernel
        .outputs
        .borrow_mut()
        .insert(HOST_ROUTES.to_owned(), Some(host_lines.to_owned()));
    match bind_eni(&binder, None, &FakeMetadata::new()) {
        Err(BindError::Eni(EniError::Unverifiable(detail))) => {
            assert_eq!(detail, "routes", "the refusal's detail");
            assert!(untouched(&binder), "the refused bind wrote");
            assert!(!mappings_path(&fixture.state_dir()).exists());
            None
        }
        bound => {
            bound.expect("the bind");
            binder.kernel.runs.borrow_mut().clear();
            binder.release(&[]).expect("the release");
            Some(binder.kernel.runs.borrow().clone())
        }
    }
}

/// Each address attribute release cannot restore refuses the bind with the
/// detail that names it: a peer, a scope other than global, a label other
/// than the device's, the deprecated flag, and any flag or word the capture
/// does not know, which release would drop.
#[test]
fn each_unrestorable_address_attribute_refuses_with_its_detail() {
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    let lifetimes = "\\       valid_lft forever preferred_lft forever\n";
    let mut wrong = Vec::new();
    for (attributes, detail) in [
        ("10.0.20.1 peer 10.0.20.2/32 scope global ens6", "peer"),
        ("10.0.20.1/24 brd 10.0.20.255 scope link ens6", "scope"),
        ("10.0.20.1/24 brd 10.0.20.255 scope global ens6:1", "label"),
        (
            "10.0.20.1/24 brd 10.0.20.255 scope global deprecated ens6",
            "deprecated",
        ),
        (
            "10.0.20.1/24 brd 10.0.20.255 scope global home ens6",
            "addresses",
        ),
        (
            "10.0.20.1/24 brd 10.0.20.255 scope global nodad ens6",
            "addresses",
        ),
        (
            "10.0.20.1/24 brd 10.0.20.255 scope global autojoin ens6",
            "addresses",
        ),
        (
            "10.0.20.1/24 brd 10.0.20.255 proto static scope global ens6",
            "addresses",
        ),
    ] {
        let state = State::listed("10.0.1.0/24 proto kernel scope link src 10.0.1.5\n");
        let line = format!("3: ens6    inet {attributes}{lifetimes}");
        let outcome = round_trip(&state, format!("{primary}{line}"));
        if !matches!(outcome, Err(BindError::Eni(EniError::Unverifiable(named))) if named == detail)
        {
            wrong.push(format!("{attributes:?} wanted {detail:?}, got {outcome:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A route with a minimum retransmission timeout refuses the bind before
/// any driver write. `ip` lists `rto_min 40ms` as `rto_min lock 40ms` and
/// takes no `lock` after `rto_min` as input, so the replay of the listed
/// words fails the release batch at that route, leaves it and the routes
/// after it unrestored, and keeps the record for a release that fails the
/// same way.
#[test]
fn a_route_with_a_minimum_retransmission_timeout_refuses_the_bind() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let state = State::listed(
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                      10.9.0.0/16 via 10.0.1.1 rto_min lock 40ms\n\
                      10.8.0.0/16 via 10.0.1.1 proto static\n",
    );
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    install(&binder.kernel, &state, primary.to_owned());
    // `ip` refuses this replay: "lock" is no value of `rto_min`.
    binder.kernel.outputs.borrow_mut().insert(
        "ip route replace 10.9.0.0/16 via 10.0.1.1 rto_min lock 40ms dev if6".to_owned(),
        None,
    );
    let record = mappings_path(&fixture.state_dir());
    match bind_eni(&binder, None, &FakeMetadata::new()) {
        Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
            assert!(untouched(&binder), "the refused bind wrote");
            assert!(!record.exists(), "the refused bind left a record");
        }
        bound => {
            let first = binder.release(&[]);
            let second = binder.release(&[]);
            panic!(
                "the bind returned {bound:?}; release returned {first:?}, then {second:?}; \
                 the record exists afterward: {}",
                record.exists()
            );
        }
    }
}

/// A route listed with an unlocked minimum retransmission timeout, as a
/// netlink sender other than `ip` leaves it, refuses the bind before any
/// driver write. `ip` takes `rto_min 40ms` as input and always locks the
/// metric it writes, so the replay of the listed words would succeed and
/// leave the route locked, which is another state than the one recorded.
/// The same route under a window metric, which `ip` writes back as
/// listed, binds.
#[test]
fn a_route_with_an_unlocked_minimum_retransmission_timeout_refuses_the_bind() {
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    for (metric, refused) in [("rto_min 40ms", true), ("window 2000", false)] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let state = State::listed(format!(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                 10.9.0.0/16 via 10.0.1.1 {metric}\n"
        ));
        install(&binder.kernel, &state, primary.to_owned());
        let bound = bind_eni(&binder, None, &FakeMetadata::new());
        if refused {
            assert!(
                matches!(bound, Err(BindError::Eni(EniError::Unverifiable("routes")))),
                "{metric}: the bind returned {bound:?}"
            );
            assert!(untouched(&binder), "{metric}: the refused bind wrote");
            assert!(
                !mappings_path(&fixture.state_dir()).exists(),
                "{metric}: the refused bind left a record"
            );
        } else {
            assert!(bound.is_ok(), "{metric}: the bind returned {bound:?}");
        }
    }
}

/// A main-table route of type `local`, `broadcast` or `anycast` refuses the
/// bind before any driver write. `ip route show` prints such a route with
/// no table word, and `ip route replace` of those words without a table
/// word writes the route to table `local`, so release would succeed with
/// the route in another table than the one the capture read it from.
#[test]
fn a_main_table_route_ip_replays_into_the_local_table_refuses_the_bind() {
    let mut admitted = Vec::new();
    for typed in [
        "local 10.5.5.5 scope host",
        "broadcast 10.5.5.255 scope link",
        "anycast 10.5.5.0 scope link",
    ] {
        let state = State::listed(format!("{PREFIX_ROUTE}{typed}\n"));
        match round_trip(&state, PRIMARY.to_owned()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {}
            outcome => admitted.push(format!(
                "main-table route {typed:?} was admitted; release: {outcome:?}"
            )),
        }
    }
    assert!(admitted.is_empty(), "{}", admitted.join("\n"));
}

/// Binds the fixture's ENI over its one address, its prefix route, `route`
/// and a later route, on a kernel that refuses release's replay of `route`.
fn bind_over_route(route: &str) -> (Fixture, super::binder::Binder<FakeKernel>) {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let state = State::listed(format!(
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5 \n{route} \n10.7.0.0/16 via 10.0.1.1 proto static \n"
    ));
    let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    install(&binder.kernel, &state, primary.to_owned());
    binder
        .kernel
        .outputs
        .borrow_mut()
        .insert(format!("ip route replace {route} dev if6"), None);
    (fixture, binder)
}

/// A route whose 32-bit realm value holds a source realm and a side above 255 refuses the bind before any driver write. `ip` lists the value as `realms <source>/<destination>` and reads each side of that form back only up to 255, so release could never replay the listed words, or the routes after them in the batch, and would keep failing with the record in place.
#[test]
fn a_route_whose_listed_realms_ip_cannot_read_back_refuses_the_bind() {
    for realms in ["realms 1/4464", "realms 256/1"] {
        let route = format!("10.8.0.0/16 via 10.0.1.1 {realms}");
        let (fixture, binder) = bind_over_route(&route);
        let record = mappings_path(&fixture.state_dir());
        match bind_eni(&binder, None, &FakeMetadata::new()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
                assert!(untouched(&binder), "{realms}: the refused bind wrote");
                assert!(!record.exists(), "{realms}: the refused bind left a record");
            }
            bound => {
                let first = binder.release(&[]);
                let second = binder.release(&[]);
                panic!(
                    "{realms}: the bind returned {bound:?}; release returned {first:?}, then {second:?}; \
                     the record exists afterward: {}",
                    record.exists()
                );
            }
        }
    }
}

/// A route whose metrics `ip` lists as whole counts binds, and release
/// replays its words unchanged: `mtu 1400 advmss 1360` lists and replays
/// as the kernel holds it.
#[test]
fn a_route_with_count_metrics_binds_and_replays_unchanged() {
    let state = State::listed(format!(
        "{PREFIX_ROUTE}10.9.0.0/16 via 10.0.1.1 mtu 1400 advmss 1360\n"
    ));
    let replayed = round_trip(&state, PRIMARY.to_owned()).expect("the route binds");
    let words = |text: &str| -> Vec<String> { text.split(' ').map(str::to_owned).collect() };
    assert_eq!(
        replayed.routes,
        vec![
            words("10.0.1.0/24 proto kernel scope link src 10.0.1.5"),
            words("10.9.0.0/16 via 10.0.1.1 mtu 1400 advmss 1360"),
        ]
    );
}

/// A route whose metric `ip` lists in words its own parser refuses binds no
/// device. The kernel takes any `u32` as `RTAX_QUICKACK` and
/// `RTAX_FASTOPEN_NO_COOKIE`, any feature bits, and a lock on either, from a
/// netlink sender other than `ip`. `ip` lists them as `quickack 5`,
/// `fastopen_no_cookie 7`, `features 0x2`, `features ecn 0xf`,
/// `features lock ecn`, `quickack lock 1`, `features ecn tcp_usec_ts`,
/// `features ecn tcp_usec_ts 0x13`, `features tcp_usec_ts 0x12` and
/// `features lock tcp_usec_ts`. Its parser takes one feature word and no
/// lock, so it takes none of those words back: the replay fails the release
/// batch at that route, leaves it and the routes after it unrestored, and
/// keeps the record.
#[test]
fn a_route_with_a_metric_ip_lists_and_refuses_as_input_refuses_the_bind() {
    let mut admitted = Vec::new();
    for metric in [
        "quickack 5",
        "fastopen_no_cookie 7",
        "features 0x2",
        "features ecn 0xf",
        "features lock ecn",
        "quickack lock 1",
        "features ecn tcp_usec_ts",
        "features ecn tcp_usec_ts 0x13",
        "features tcp_usec_ts 0x12",
        "features lock tcp_usec_ts",
    ] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let route = format!("10.9.0.0/16 via 10.0.1.1 proto static {metric}");
        let state = State::listed(format!(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n{route}\n\
                 10.8.0.0/16 via 10.0.1.1 proto static\n"
        ));
        let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
        install(&binder.kernel, &state, primary.to_owned());
        // `ip` refuses this replay: the words are no input of the metric.
        binder
            .kernel
            .outputs
            .borrow_mut()
            .insert(format!("ip route replace {route} dev if6"), None);
        let record = mappings_path(&fixture.state_dir());
        match bind_eni(&binder, None, &FakeMetadata::new()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
                assert!(untouched(&binder), "the refused bind wrote");
                assert!(!record.exists(), "the refused bind left a record");
            }
            bound => {
                let first = binder.release(&[]);
                let second = binder.release(&[]);
                admitted.push(format!(
                    "{metric}: the bind returned {bound:?}; release returned {first:?}, then \
                     {second:?}; the record exists afterward: {}",
                    record.exists()
                ));
            }
        }
    }
    assert!(admitted.is_empty(), "{}", admitted.join("\n"));
}

/// The same metrics in the words `ip` takes back bind, and release replays
/// them as listed: `quickack 1`, `fastopen_no_cookie 1`, `features ecn` and
/// `features tcp_usec_ts`.
#[test]
fn a_route_with_a_metric_ip_takes_back_round_trips_through_the_record_to_release() {
    let main = [
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5",
        "10.9.0.0/16 via 10.0.1.1 proto static features ecn quickack 1 fastopen_no_cookie 1",
        "10.10.0.0/16 via 10.0.1.1 proto static features tcp_usec_ts quickack 1",
    ];
    let state = State {
        addresses: vec![Address {
            local: Ipv4Addr::new(10, 0, 1, 5),
            prefix: 24,
            broadcast: None,
            metric: None,
            no_prefix_route: false,
        }],
        routes: main
            .iter()
            .map(|route| route.split(' ').map(str::to_owned).collect())
            .collect(),
        route_lines: format!("{}\n{}\n{}\n", main[0], main[1], main[2]),
    };
    let primary = "3: ens6    inet 10.0.1.5/24 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    let replayed = round_trip(&state, primary.to_owned()).unwrap();
    assert_eq!(replayed, expected(&state));
}

/// A route listed with a flag word `ip` prints and takes back as no input
/// refuses the bind before any driver write. A netlink sender can set the
/// offload and trap flags on a route; `ip` lists them as `offload` and
/// `trap` and refuses each as input, so the replay of the listed words fails
/// the release batch at that route, leaves it and the routes after it
/// unrestored, and keeps the record for a release that fails the same way.
#[test]
fn a_route_with_a_flag_word_ip_lists_and_refuses_as_input_refuses_the_bind() {
    let mut admitted = Vec::new();
    for flag in ["offload", "trap"] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let route = format!("10.9.0.0/16 via 10.0.1.1 proto static {flag}");
        let state = State::listed(format!(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n{route}\n\
                 10.8.0.0/16 via 10.0.1.1 proto static\n"
        ));
        let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
        install(&binder.kernel, &state, primary.to_owned());
        // `ip` refuses this replay: the flag word is no input.
        binder
            .kernel
            .outputs
            .borrow_mut()
            .insert(format!("ip route replace {route} dev if6"), None);
        let record = mappings_path(&fixture.state_dir());
        match bind_eni(&binder, None, &FakeMetadata::new()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
                assert!(untouched(&binder), "the refused bind wrote");
                assert!(!record.exists(), "the refused bind left a record");
            }
            bound => {
                let first = binder.release(&[]);
                let second = binder.release(&[]);
                admitted.push(format!(
                    "{flag}: the bind returned {bound:?}; release returned {first:?}, then \
                     {second:?}; the record exists afterward: {}",
                    record.exists()
                ));
            }
        }
    }
    assert!(admitted.is_empty(), "{}", admitted.join("\n"));
}

/// A route listed with `onlink`, the flag word `ip` takes back, binds, and
/// release replays it as listed.
#[test]
fn a_route_with_the_onlink_flag_round_trips_through_the_record_to_release() {
    let main = [
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5",
        "10.9.0.0/16 via 10.7.7.7 proto static onlink",
    ];
    let state = State {
        addresses: vec![Address {
            local: Ipv4Addr::new(10, 0, 1, 5),
            prefix: 24,
            broadcast: None,
            metric: None,
            no_prefix_route: false,
        }],
        routes: main
            .iter()
            .map(|route| route.split(' ').map(str::to_owned).collect())
            .collect(),
        route_lines: format!("{}\n{}\n", main[0], main[1]),
    };
    let primary = "3: ens6    inet 10.0.1.5/24 scope global ens6\\       valid_lft forever preferred_lft forever\n";
    let replayed = round_trip(&state, primary.to_owned()).unwrap();
    assert_eq!(replayed, expected(&state));
}

/// A route whose next hop carries the kernel's offload or trap flag refuses
/// the bind before any driver write. Linux keeps `RTNH_F_OFFLOAD` and
/// `RTNH_F_TRAP` from the `rtm_flags` of a netlink sender, `ip` lists them
/// as `offload` and `trap`, and `ip route replace` takes neither word, so the
/// replay of the listed words fails the release batch at that route, leaves
/// it unrestored, and keeps the record for a release that fails the same
/// way.
#[test]
fn a_route_listed_with_a_hardware_flag_refuses_the_bind() {
    for flag in ["offload", "trap"] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let route = format!("10.9.0.0/16 via 10.0.1.1 {flag}");
        let state = State::listed(format!(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                 10.8.0.0/16 via 10.0.1.1 proto static\n\
                 {route}\n"
        ));
        let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
        install(&binder.kernel, &state, primary.to_owned());
        // `ip` refuses this replay: "Error: either "to" is duplicate, or "offload" is a garbage."
        binder
            .kernel
            .outputs
            .borrow_mut()
            .insert(format!("ip route replace {route} dev if6"), None);
        let record = mappings_path(&fixture.state_dir());
        match bind_eni(&binder, None, &FakeMetadata::new()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
                assert!(untouched(&binder), "{flag}: the refused bind wrote");
                assert!(!record.exists(), "{flag}: the refused bind left a record");
            }
            bound => {
                let first = binder.release(&[]);
                let second = binder.release(&[]);
                panic!(
                    "{flag}: the bind returned {bound:?}; release returned {first:?}, then {second:?}; \
                     the record exists afterward: {}",
                    record.exists()
                );
            }
        }
    }
}

/// A route the kernel marks offloaded, trapped or failed to offload refuses
/// the bind before any driver write. A driver that offloads the FIB sets
/// `RTM_F_OFFLOAD`, `RTM_F_TRAP` or `RTM_F_OFFLOAD_FAILED` on a route's
/// listing, `ip` lists them as `rt_offload`, `rt_trap` and
/// `rt_offload_failed`, and `ip route replace` takes none of the words, so
/// the replay of the listed words fails the release batch at that route,
/// leaves it unrestored, and keeps the record for a release that fails the
/// same way.
#[test]
fn a_route_listed_with_a_route_offload_flag_refuses_the_bind() {
    for flag in ["rt_offload", "rt_trap", "rt_offload_failed"] {
        let fixture = Fixture::new(4096);
        let binder = new_binder(&fixture);
        let route = format!("10.9.0.0/16 via 10.0.1.1 {flag}");
        let state = State::listed(format!(
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5\n\
                 10.8.0.0/16 via 10.0.1.1 proto static\n\
                 {route}\n"
        ));
        let primary = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n";
        install(&binder.kernel, &state, primary.to_owned());
        // `ip` refuses this replay: "Error: either "to" is duplicate, or "rt_trap" is a garbage."
        binder
            .kernel
            .outputs
            .borrow_mut()
            .insert(format!("ip route replace {route} dev if6"), None);
        let record = mappings_path(&fixture.state_dir());
        match bind_eni(&binder, None, &FakeMetadata::new()) {
            Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
                assert!(untouched(&binder), "{flag}: the refused bind wrote");
                assert!(!record.exists(), "{flag}: the refused bind left a record");
            }
            bound => {
                let first = binder.release(&[]);
                let second = binder.release(&[]);
                panic!(
                    "{flag}: the bind returned {bound:?}; release returned {first:?}, then {second:?}; \
                     the record exists afterward: {}",
                    record.exists()
                );
            }
        }
    }
}

const LIFETIME: &str = "ens6\\       valid_lft forever preferred_lft forever\n";

/// A state whose device holds 10.0.1.5/24 and `second`/8 at scope global,
/// with the routes Linux 6.12 lists for the two, and its address listing.
fn two_prefixes(second: Ipv4Addr) -> (State, String) {
    let address = |local, prefix| Address {
        local,
        prefix,
        broadcast: None,
        metric: None,
        no_prefix_route: false,
    };
    let [first, ..] = second.octets();
    let main = [
        "10.0.1.0/24 proto kernel scope link src 10.0.1.5".to_owned(),
        format!("{first}.0.0.0/8 proto kernel scope link src {second}"),
    ];
    let route_lines = format!(
        "{} \n{} \n\
         local 10.0.1.5 table local proto kernel scope host src 10.0.1.5 \n\
         broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5 \n\
         local {second} table local proto kernel scope host src {second} \n\
         broadcast {first}.255.255.255 table local proto kernel scope link src {second} \n",
        main[0], main[1]
    );
    let state = State {
        addresses: vec![address(Ipv4Addr::new(10, 0, 1, 5), 24), address(second, 8)],
        routes: main
            .iter()
            .map(|route| route.split(' ').map(str::to_owned).collect())
            .collect(),
        route_lines,
    };
    let address_lines = format!(
        "3: ens6    inet 10.0.1.5/24 scope global {LIFETIME}3: ens6    inet {second}/8 scope global {LIFETIME}"
    );
    (state, address_lines)
}

/// An address in 127.0.0.0/8 at scope `global` refuses the bind before any
/// driver write. Release replays an address with no scope word, and `ip addr
/// replace` without one assigns an address in 127.0.0.0/8 at scope `host`,
/// so release would succeed with the address at another scope than the one
/// the capture read.
#[test]
fn a_loopback_range_address_at_scope_global_refuses_the_bind() {
    let (state, address_lines) = two_prefixes(Ipv4Addr::new(127, 0, 0, 2));
    match round_trip(&state, address_lines) {
        Err(BindError::Eni(EniError::Unverifiable("scope"))) => {}
        outcome => panic!("127.0.0.2/8 at scope global was admitted; release: {outcome:?}"),
    }
}

/// The same state with the second address outside 127.0.0.0/8 binds, and
/// release replays both addresses: `ip addr replace` without a scope word
/// assigns them at scope `global`.
#[test]
fn an_address_beside_the_loopback_range_at_scope_global_binds_and_replays() {
    let (state, address_lines) = two_prefixes(Ipv4Addr::new(126, 0, 0, 2));
    let replayed = round_trip(&state, address_lines).expect("126.0.0.2/8 binds");
    assert_eq!(replayed, expected(&state));
}

/// The route commands of a release batch, in batch order, without the
/// device word.
fn route_commands(batch: &[String]) -> Vec<String> {
    batch
        .iter()
        .filter_map(|run| {
            run.strip_prefix("ip route replace ")?
                .strip_suffix(" dev if6")
                .map(str::to_owned)
        })
        .collect()
}

/// The primary address without its prefix route, so only listed routes reach a gateway.
const BARE_PRIMARY: &str = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global noprefixroute ens6\\       valid_lft forever preferred_lft forever\n";

/// Release replays host-scope routes, then link-scope routes, then the
/// others, each group in listed order, because the kernel resolves a
/// gateway only through a route of a nearer scope. The listing puts every
/// dependent route ahead of the route that reaches its gateway: a route
/// through a gateway ahead of its link route, and a link-scope route through
/// a gateway ahead of its host route. A link route whose protocol the host
/// names `via` is a link route.
#[test]
fn release_replays_each_route_after_the_routes_that_reach_its_gateway() {
    let listed = "10.0.0.0/8 via 10.0.8.1 \n\
                  10.0.8.0/24 via 10.0.9.1 scope link \n\
                  10.0.9.1 scope host \n\
                  10.2.0.0/16 via 10.0.1.1 proto static \n\
                  10.0.1.0/24 proto via scope link src 10.0.1.5 \n\
                  10.64.0.0/16 via 10.0.1.1 onlink \n";
    let batch = released_batch(BARE_PRIMARY, listed).expect("the bind");
    assert_eq!(
        route_commands(&batch),
        [
            "10.0.9.1 scope host",
            "10.0.8.0/24 via 10.0.9.1 scope link",
            "10.0.1.0/24 proto via scope link src 10.0.1.5",
            "10.0.0.0/8 via 10.0.8.1",
            "10.2.0.0/16 via 10.0.1.1 proto static",
            "10.64.0.0/16 via 10.0.1.1 onlink",
        ]
    );
}

/// `ip -batch` lists the host's device-less routes under every device. The
/// capture passes them over: the bind records the ENI's own routes alone,
/// and release replays no command for a host route, in main or in another
/// table.
#[test]
fn a_device_less_host_route_in_the_eni_listing_is_passed_over() {
    for route in [
        "blackhole 10.9.0.0/16",
        "unreachable 10.8.0.0/16 metric 5",
        "prohibit 10.7.0.0/16 proto static",
        "throw 10.6.0.0/16",
        "nat 10.9.9.33 scope nowhere",
        "xresolve 10.9.9.38 scope nowhere",
        "blackhole 10.5.0.0/16 table 100",
        "unreachable 10.4.0.0/16 rto_min lock 40ms",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n10.3.0.0/16 via 10.0.1.1 \n");
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{route}: refused"));
        assert_eq!(
            route_commands(&batch),
            [
                "10.0.1.0/24 proto kernel scope link src 10.0.1.5",
                "10.3.0.0/16 via 10.0.1.1"
            ],
            "{route}"
        );
    }
}

/// A main-table host route that shares a recorded route's replace key
/// refuses the bind: release's `route replace` of the ENI route would write
/// over the host's route. The same host route in another table, or under
/// another metric, admits the bind. A protocol the host names `table`,
/// `dead` or `linkdown` is the value of `proto`, and the tunnel's `tos` in
/// an `encap` block hides the route's own type of service, so such host
/// routes refuse under the recorded destination and metric. A host route
/// the bind would remove refuses too: a main-table one whose source address
/// is the device's, and one through a nexthop object the listing names no
/// other device for. So does a line with an attribute that has no value.
#[test]
fn a_device_less_host_route_under_a_recorded_route_s_key_refuses_the_bind() {
    let listed =
        |host: &str| format!("{PREFIX_ROUTE}10.9.0.0/16 via 10.0.1.1 metric 5 \n{host} \n");
    for host in [
        "blackhole 10.9.0.0/16 metric 5",
        "unreachable 10.9.0.0/16 proto static metric 5",
        "blackhole 10.9.0.0/16 proto table metric 5",
        "blackhole 10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 metric 5",
        "blackhole 10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 7 tos 0x10 \
         metric 5",
        "unreachable 10.9.0.0/16 metric 5 rto_min lock 40ms",
        "blackhole 10.9.0.0/16 proto dead metric 5",
        "blackhole 10.9.0.0/16 proto linkdown metric 5",
        "blackhole 10.99.0.0/16 src 10.0.1.5",
        "unreachable 10.99.0.0/16 proto static src 10.0.1.5 metric 9",
        "blackhole 10.99.0.0/16 nhid 8",
        "blackhole 10.99.0.0/16 metric",
    ] {
        assert_eq!(released_batch(PRIMARY, &listed(host)), None, "{host}");
    }
    for host in [
        "blackhole 10.9.0.0/16 metric 6",
        "blackhole 10.9.0.0/16",
        "blackhole 10.9.0.0/16 table 100 metric 5",
        "blackhole 10.9.0.0/16 table 100 proto table metric 5",
        "blackhole 10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 metric 6",
        "blackhole 10.99.0.0/16 src 10.0.2.9",
        "blackhole 10.99.0.0/16 table 100 src 10.0.1.5",
        "blackhole 10.99.0.0/16 proto src",
        "blackhole 10.99.0.0/16 proto nhid",
        "blackhole 10.99.0.0/16 nhid 8 via 10.1.1.1 dev d1",
    ] {
        assert!(released_batch(PRIMARY, &listed(host)).is_some(), "{host}");
    }
}

/// A realm lists as `realm <n>`, or as `realms <from>/<to>` when the route
/// has a source realm. Release replays a numeric realm, and a numeric pair
/// with both sides at most 255. The capture reads the realm at its
/// attribute, so a protocol the host names `realms` hides no pair, and it
/// refuses a side listed by name, which one `ip -batch` process can read
/// back as another realm.
#[test]
fn a_route_s_realm_binds_only_in_the_numeric_forms_ip_reads_back() {
    for realm in [
        "realm 7",
        "realm 4464",
        "realms 5/6",
        "realms 255/255",
        "proto realms realms 3/5",
        "proto realm",
    ] {
        let route = format!("10.8.0.0/16 via 10.0.1.1 {realm}");
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{realm}: refused"));
        assert!(
            route_commands(&batch).contains(&route),
            "{realm}: {batch:?}"
        );
    }
    for realm in [
        "realms 1/4464",
        "realms 256/1",
        "proto realms realms 1/4464",
        "congctl realms realms 300/2",
        "realm cosmos",
        "realms cosmos/6",
        "realms 5/cosmos",
        "realms 5",
    ] {
        let listed = format!("{PREFIX_ROUTE}10.8.0.0/16 via 10.0.1.1 {realm} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{realm}");
    }
}

/// A route with a tunnel encapsulation refuses the bind. `ip` lists an
/// `encap ip` type of service and an `encap ip6` traffic class in decimal
/// and reads the replayed word in hexadecimal, lists a seg6 segment list in
/// a form its parser refuses, and lists a route's own type of service after
/// the tunnel's, where its parser reads both as the tunnel's. The capture
/// refuses at the `encap` word, so a block with Geneve, VXLAN or ERSPAN
/// options, which `ip -o` lists after a line join, refuses the same way.
#[test]
fn a_route_with_a_tunnel_encapsulation_refuses_the_bind() {
    for route in [
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 via 10.0.1.1",
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 16 via 10.0.1.1",
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 tos 0x10 via 10.0.1.1",
        "10.9.0.0/16  encap ip6 id 5 src :: dst 2001:db8::1 hoplimit 0 tc 16 via 10.0.1.1",
        "10.9.0.0/16  encap seg6 mode encap segs 1 [ 2001:db8::1 ] via 10.0.1.1",
        "10.9.0.0/16  encap mpls 100 via 10.0.1.1",
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 \\\tgeneve_opts 66:80:00800022 via 10.0.1.1",
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 \\\tvxlan_opts 100 via 10.0.1.1",
        "10.9.0.0/16  encap ip id 5 src 0.0.0.0 dst 192.0.2.1 ttl 0 tos 0 \\\terspan_opts 2:0:1:63 via 10.0.1.1",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{route}");
    }
}

/// `ip` lists no scope word for a route at scope global, and `ip route
/// replace` without one writes a route with no gateway, and a multicast
/// route, at scope link. Such a listing refuses the bind; the same routes
/// with their scope listed, and a unicast route through a gateway, bind and
/// replay as listed.
#[test]
fn a_route_listed_without_the_scope_replay_would_change_refuses_the_bind() {
    for route in [
        "10.7.0.0/16",
        "10.7.0.0/16 proto static metric 5",
        "multicast 239.1.0.0/16 via 10.0.1.1",
        "multicast 239.1.0.0/16",
        "10.7.0.0/16 proto scope",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{route}");
    }
    for route in [
        "10.7.0.0/16 scope link",
        "10.7.0.0/16 proto static scope host",
        "multicast 239.1.0.0/16 scope link",
        "10.7.0.0/16 via 10.0.1.1",
        "10.7.0.0/16 via 10.0.1.1 proto static metric 5",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{route}: refused"));
        assert!(
            route_commands(&batch).iter().any(|run| run == route),
            "{route}: {batch:?}"
        );
    }
}

/// `ip` lists a protocol, a scope, a type of service and a congestion
/// control by the name the host's tables give it. The capture takes the
/// word after each of those attributes as a value, so a name that spells a
/// refused word, or another attribute, binds and replays unchanged. The same
/// word as an attribute of its own refuses the bind.
#[test]
fn a_name_that_spells_a_refused_word_is_a_value_and_binds() {
    for route in [
        "10.8.0.0/16 via 10.0.1.1 proto trap",
        "10.8.0.0/16 via 10.0.1.1 proto rtt metric 5",
        "10.8.0.0/16 via 10.0.1.1 proto rto_min",
        "10.8.0.0/16 via 10.0.1.1 proto encap",
        "10.8.0.0/16 via 10.0.1.1 proto nhid",
        "10.8.0.0/16 via 10.0.1.1 proto nexthop",
        "10.8.0.0/16 via 10.0.1.1 proto table",
        "10.8.0.0/16 via 10.0.1.1 proto dead metric 5",
        "10.8.0.0/16 via 10.0.1.1 proto linkdown",
        "10.8.0.0/16 proto encap scope 253",
        "10.8.0.0/16 tos offload via 10.0.1.1",
        "10.8.0.0/16 via 10.0.1.1 congctl lock rttvar",
        "10.8.0.0/16 proto metric scope link",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{route}: refused"));
        assert!(
            route_commands(&batch).iter().any(|run| run == route),
            "{route}: {batch:?}"
        );
    }
    // A state flag stands where an attribute may, and release replays the route without it.
    let listed = format!("{PREFIX_ROUTE}10.8.0.0/16 via 10.0.1.1 proto dead dead linkdown \n");
    let batch = released_batch(PRIMARY, &listed).expect("the flagged route binds");
    assert!(
        route_commands(&batch).contains(&"10.8.0.0/16 via 10.0.1.1 proto dead".to_owned()),
        "{batch:?}"
    );
    for route in [
        "10.8.0.0/16 via 10.0.1.1 trap",
        "10.8.0.0/16 via 10.0.1.1 proto static rtt 300ms",
        "10.8.0.0/16 via 10.0.1.1 rto_min 40ms",
        "10.8.0.0/16 via 10.0.1.1 proto trap offload",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{route}");
    }
}

/// A word outside the attributes release replays refuses the bind, and so
/// does an attribute whose value is missing or malformed.
#[test]
fn a_route_word_outside_the_replayed_attributes_refuses_the_bind() {
    for route in [
        "10.8.0.0/16 via 10.0.1.1 pervasive",
        "10.8.0.0/16 via 10.0.1.1 mark 5",
        "10.8.0.0/16 via 10.0.1.1 uid 0",
        "10.8.0.0/16 from 10.0.1.0/24 via 10.0.1.1",
        "10.8.0.0/16 via 10.0.1.1 expires 30sec",
        "10.8.0.0/16 via 10.0.1.1 metric",
        "10.8.0.0/16 via 10.0.1.1 metric five",
        "10.8.0.0/16 via gateway",
        "10.8.0.0/16 via inet6 10.0.1.1",
        "10.8.0.0/16 via 10.0.1.1 src ens6",
        "10.8.0.0/33 via 10.0.1.1",
        "ten.eight/16 via 10.0.1.1",
        "10.8.0.0/16 via 10.0.1.1 mtu lock",
        "10.8.0.0/16 via 10.0.1.1 mtu big",
        "10.8.0.0/16 via 10.0.1.1 scope via",
        "10.8.0.0/16 scope uplink",
        "10.8.0.0/16 scope 256",
        "multicast default via inet6 fe80::1 scope link",
        "10.8.0.0/16 via 10.0.1.1 dev ens6",
        "10.8.0.0/16 nexthop via 10.0.1.1 weight 1",
        "10.8.0.0/16 via 10.0.1.1 proto zebra\u{a0}tos 0x10",
        "10.8.0.0/16 via 10.0.1.1 proto zebra\u{2003}onlink",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{route}");
    }
    for route in [
        "10.8.0.0/16 via inet6 fe80::1",
        "10.8.0.1 via 10.0.1.1 src 10.0.1.5 metric 4294967295",
        "10.8.0.0/16 via 10.0.1.1 mtu lock 1400 advmss 1360 window 1000 initcwnd 10 hoplimit 64",
        "10.8.0.0/16 via 10.0.1.1 ssthresh 20",
        "10.8.0.0/16 via 10.0.1.1 cwnd lock 10",
        "10.8.0.0/16 via 10.0.1.1 initrwnd 20",
        "10.8.0.0/16 via 10.0.1.1 reordering 5",
        "10.8.0.1 scope 254 src 10.0.1.5",
        "multicast 239.2.0.0/16 via inet6 fe80::1 scope link",
    ] {
        let listed = format!("{PREFIX_ROUTE}{route} \n");
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{route}: refused"));
        assert!(
            route_commands(&batch).iter().any(|run| run == route),
            "{route}: {batch:?}"
        );
    }
}

/// `ip` lists `rtt` and `rttvar` rounded: in whole milliseconds below one
/// second and in seconds above it. Either form refuses the bind.
#[test]
fn a_route_with_a_listed_rtt_or_rttvar_refuses_the_bind() {
    for metric in [
        "rtt 300ms",
        "rttvar 150ms",
        "rtt 1.625s",
        "rttvar 2s",
        "rtt lock 300ms",
    ] {
        let listed = format!("{PREFIX_ROUTE}10.8.0.0/16 via 10.0.1.1 {metric} \n");
        assert_eq!(released_batch(PRIMARY, &listed), None, "{metric}");
    }
}

/// `ip route replace` finds an existing route by its destination, type of
/// service and metric. Two listed routes under one such key refuse the bind,
/// whatever their gateways and types: release would write the second over
/// the first. Routes to one destination that differ in metric or in type of
/// service alone bind, and release replays both.
#[test]
fn two_routes_under_one_replace_key_refuse_the_bind() {
    for pair in [
        ["10.9.0.0/16 via 10.0.1.1", "10.9.0.0/16 via 10.0.1.2"],
        [
            "10.9.0.0/16 via 10.0.1.1 metric 5",
            "10.9.0.0/16 scope link metric 5",
        ],
        [
            "10.9.0.0/16 tos 0x10 via 10.0.1.1",
            "10.9.0.0/16 tos 0x10 via 10.0.1.2 proto static",
        ],
        [
            "multicast 239.1.0.0/16 scope link",
            "239.1.0.0/16 scope link",
        ],
        [
            "10.9.0.0/16 via 10.0.1.1 proto metric",
            "10.9.0.0/16 via 10.0.1.2 proto tos",
        ],
        [
            "10.9.0.0/16 via 10.0.1.1 proto metric src 10.0.1.5",
            "10.9.0.0/16 via 10.0.1.2 proto tos onlink",
        ],
    ] {
        let listed = format!(
            "{PREFIX_ROUTE}{} \n10.3.0.0/16 via 10.0.1.1 \n{} \n",
            pair[0], pair[1]
        );
        assert_eq!(released_batch(PRIMARY, &listed), None, "{pair:?}");
    }
    for pair in [
        [
            "10.9.0.0/16 via 10.0.1.1 metric 5",
            "10.9.0.0/16 via 10.0.1.2 metric 6",
        ],
        [
            "10.9.0.0/16 via 10.0.1.1",
            "10.9.0.0/16 tos 0x10 via 10.0.1.2",
        ],
        [
            "10.9.0.0/16 tos 0x10 via 10.0.1.1",
            "10.9.0.0/16 tos 0x20 via 10.0.1.1",
        ],
        [
            "10.9.0.0/16 via 10.0.1.1 proto metric",
            "10.9.0.0/16 via 10.0.1.2 metric 7",
        ],
        [
            "10.9.0.0/16 via 10.0.1.1 proto metric metric 5",
            "10.9.0.0/16 via 10.0.1.2 proto metric metric 6",
        ],
    ] {
        let listed = format!("{PREFIX_ROUTE}{} \n{} \n", pair[0], pair[1]);
        let batch = released_batch(PRIMARY, &listed).unwrap_or_else(|| panic!("{pair:?}: refused"));
        let routes = route_commands(&batch);
        for route in pair {
            assert!(routes.iter().any(|run| run == route), "{pair:?}: {batch:?}");
        }
    }
}

/// `ip` before 6.10 lists no device-less route under a device, so the
/// capture reads every table's by their type and judges each as one listed
/// under the device: a shared replace key or the device's address as
/// source in the main table, or a nexthop object on the device in any
/// table, refuses the bind. A nexthop object the listing names another
/// device for stays when the ENI leaves. `ip` 6.10 lists such a route both
/// ways, which counts once.
#[test]
fn a_host_route_listed_by_its_type_alone_is_judged_as_one_listed_under_the_device() {
    let listed = format!("{PREFIX_ROUTE}10.9.0.0/16 via 10.0.1.1 metric 5 \n");
    for host in [
        "blackhole 10.9.0.0/16 metric 5",
        "blackhole 10.99.0.0/16 src 10.0.1.5",
        "blackhole 10.99.0.0/16 nhid 8",
        "blackhole 10.99.0.0/16 nhid 8 via 10.0.1.1 dev ens6",
        "blackhole 10.99.0.0/16 nhid 8 nexthop via 10.1.1.1 dev d1 weight 1",
        "blackhole 10.99.0.0/16 nhid 8 via 10.0.1.1 dev ens6 table 7",
    ] {
        let batch = released_beside(PRIMARY, &listed, &format!("{host} \n"));
        assert_eq!(batch, None, "{host}");
    }
    for host in [
        "blackhole 10.9.0.0/16 metric 6",
        "blackhole 10.99.0.0/16 nhid 8 via 10.1.1.1 dev d1",
        "blackhole 10.99.0.0/16 proto static",
        "blackhole 10.9.0.0/16 table 7 metric 5",
        "blackhole 10.99.0.0/16 table 7 src 10.0.1.5",
        "blackhole 10.99.0.0/16 nhid 8 via 10.1.1.1 dev d1 table 7",
    ] {
        let batch = released_beside(PRIMARY, &listed, &format!("{host} \n"));
        assert!(batch.is_some(), "{host}");
        let both = format!("{listed}{host} \n");
        let batch = released_beside(PRIMARY, &both, &format!("{host} \n"));
        assert!(batch.is_some(), "{host}, listed both ways");
    }
}

/// A main-table route of another device refuses the bind when release
/// would write over it or the bind would remove it: one under a recorded
/// route's destination, type of service and metric, which `route replace`
/// overwrites, and one whose `src` is an address of the device, which the
/// kernel removes with the address. A multipath route of other devices is
/// judged by the words ahead of its next hops. Every other route of another
/// device is passed over, its local-table entries included, and so is the
/// complete listing's own copy of each route of the device.
#[test]
fn a_route_of_another_device_the_bind_or_release_would_change_refuses_the_bind() {
    let listed = format!("{PREFIX_ROUTE}10.9.0.0/16 via 10.0.1.1 metric 5 \n");
    for host in [
        "10.9.0.0/16 via 10.1.1.1 dev d1 metric 5",
        "10.0.1.0/24 dev d1 proto kernel scope link src 10.0.1.7",
        "10.9.0.0/16 metric 5 \\\tnexthop via 10.1.1.1 dev d1 weight 1 \\\tnexthop via 10.2.1.1 dev d2 weight 1",
        "10.50.0.0/16 via 10.1.1.1 dev d1 src 10.0.1.5",
        "10.50.0.0/16 src 10.0.1.5 \\\tnexthop via 10.1.1.1 dev d1 weight 1 \\\tnexthop via 10.2.1.1 dev d2 weight 1",
    ] {
        let batch = released_beside(PRIMARY, &listed, &format!("{host} \n"));
        assert_eq!(batch, None, "{host}");
    }
    let alone = released_beside(PRIMARY, &listed, "").expect("the bind");
    let others = "10.0.1.0/24 dev ens6 proto kernel scope link src 10.0.1.5 \n\
        10.9.0.0/16 via 10.0.1.1 dev ens6 metric 5 \n\
        local 10.0.1.5 dev ens6 table local proto kernel scope host src 10.0.1.5 \n\
        10.1.1.0/24 dev d1 proto kernel scope link src 10.1.1.5 \n\
        local 10.1.1.5 dev d1 table local proto kernel scope host src 10.1.1.5 \n\
        local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1 \n\
        10.9.0.0/16 via 10.1.1.1 dev d1 metric 6 \n\
        10.9.0.0/16 via 10.1.1.1 dev d1 table 7 metric 5 \n\
        10.50.0.0/16 via 10.1.1.1 dev d1 src 10.1.1.5 \n\
        10.50.0.0/16 via 10.1.1.1 dev d1 table 7 src 10.0.1.5 \n\
        10.60.0.0/16 \\\tnexthop via 10.1.1.1 dev d1 weight 1 \\\tnexthop via 10.2.1.1 dev d2 weight 1 \n\
        10.70.0.0/16 nhid 8 via 10.1.1.1 dev d1 \n";
    assert_eq!(
        released_beside(PRIMARY, &listed, others),
        Some(alone),
        "routes the bind and release leave alone"
    );
}

/// `ip` before 6.10 leaves out of a listing by device each route that names
/// its device only in a next hop or in a nexthop object: a multipath route,
/// and a route through an object on a host that lists no device for one.
/// The bind removes such a route of the device, a multipath one whole, so
/// the complete listing's copy refuses the bind: a multipath route with a
/// next hop on the device, and a route that names no device at all.
#[test]
fn a_route_of_the_device_listed_only_in_the_complete_listing_refuses_the_bind() {
    for host in [
        "10.9.0.0/16 \\\tnexthop via 10.0.1.1 dev ens6 weight 1 \\\tnexthop via 10.1.1.1 dev d1 weight 1",
        "10.9.0.0/16 \\\tnexthop via 10.1.1.1 dev d1 weight 1 \\\tnexthop via 10.0.1.1 dev ens6 weight 1",
        "10.5.0.0/16 nhid 5",
        "10.5.0.0/16 nhid 5 proto static metric 20",
    ] {
        let batch = released_beside(PRIMARY, PREFIX_ROUTE, &format!("{host} \n"));
        assert_eq!(batch, None, "{host}");
    }
}

/// A route through a gateway binds only when release replays a route to the
/// gateway first. The kernel takes a gateway that is one of the device's
/// addresses, or that a unicast route of the device with no type of service
/// covers at a scope nearer than the gateway route's and at least `link`,
/// when its lookup returns that route before any entry of another type.
/// It keeps a gateway route listed after the address that reached it is
/// removed, and refuses the replay of such a route. An `onlink` route needs
/// no route to its gateway.
#[test]
fn a_gateway_route_binds_only_when_release_replays_a_route_to_its_gateway() {
    let second = |flags: &str| {
        format!(
            "{PRIMARY}3: ens6    inet 10.0.5.5/24 brd 10.0.5.255 scope global {flags}ens6\\       valid_lft forever preferred_lft forever\n"
        )
    };
    for (addresses, routes) in [
        (PRIMARY.to_owned(), "10.9.0.0/16 via 10.0.5.1"),
        (PRIMARY.to_owned(), "10.9.0.0/16 via 10.0.1.1 scope link"),
        (
            PRIMARY.to_owned(),
            "10.0.5.0/24 tos 0x10 scope link \n10.9.0.0/16 via 10.0.5.1",
        ),
        (
            PRIMARY.to_owned(),
            "multicast 10.0.5.0/24 scope link \n10.9.0.0/16 via 10.0.5.1",
        ),
        (
            PRIMARY.to_owned(),
            "10.0.5.0/24 via 10.0.1.1 \n10.9.0.0/16 via 10.0.5.1",
        ),
        (
            PRIMARY.to_owned(),
            "10.0.5.1 scope link \n10.9.0.0/16 via 10.0.5.1 scope link",
        ),
        (PRIMARY.to_owned(), "10.9.0.0/16 via inet6 2001:db8::1"),
        (second("noprefixroute "), "10.9.0.0/16 via 10.0.5.1"),
    ] {
        let listed = format!("{PREFIX_ROUTE}{routes} \n");
        assert_eq!(released_batch(&addresses, &listed), None, "{routes}");
    }
    for (addresses, routes) in [
        (PRIMARY.to_owned(), "10.9.0.0/16 via 10.0.5.1 onlink"),
        (
            PRIMARY.to_owned(),
            "10.9.0.0/16 via 10.0.5.1 \n10.0.5.0/24 scope link",
        ),
        (
            PRIMARY.to_owned(),
            "10.9.0.0/16 via 10.0.6.1 \n10.0.6.0/24 via 10.0.5.1 scope link \n10.0.5.1 scope host",
        ),
        (PRIMARY.to_owned(), "10.9.0.0/16 via 10.0.1.5"),
        (PRIMARY.to_owned(), "10.9.0.0/16 via 10.0.1.5 scope link"),
        (PRIMARY.to_owned(), "10.9.0.0/16 via inet6 fe80::1"),
        (
            PRIMARY.to_owned(),
            "10.9.0.0/16 via inet6 2001:db8::1 onlink",
        ),
        (second(""), "10.9.0.0/16 via 10.0.5.1"),
    ] {
        let listed = format!("{PREFIX_ROUTE}{routes} \n");
        assert!(
            released_batch(&addresses, &listed).is_some(),
            "{routes}: refused"
        );
    }
}

/// An address reaches a gateway by its prefix route only as the primary of
/// its network and prefix length. The kernel adds the prefix route with the
/// first address release assigns there and none with a later one, so a
/// primary with `noprefixroute` leaves its secondaries without a route to a
/// gateway in the prefix. An address of another prefix length is the
/// primary of its own prefix.
#[test]
fn a_secondary_address_brings_no_prefix_route_to_a_gateway() {
    let beside =
        |second: &str| format!("{BARE_PRIMARY}3: ens6    inet {second} scope global {LIFETIME}");
    let route = "10.9.0.0/16 via 10.0.1.1 \n";
    assert_eq!(
        released_batch(&beside("10.0.1.6/24 brd 10.0.1.255"), route),
        None,
        "a later address of the primary's prefix"
    );
    assert_eq!(
        released_batch(
            &beside("10.0.1.6/24 brd 10.0.1.255").replace("global ens6", "global secondary ens6"),
            route
        ),
        None,
        "the same address listed as a secondary"
    );
    assert!(
        released_batch(&beside("10.0.1.6/25 brd 10.0.1.127"), route).is_some(),
        "the primary of a longer prefix: refused"
    );
}

/// An address whose network lies in 0.0.0.0/8 reaches no gateway by its
/// prefix route: the kernel adds no prefix route for such a network, which
/// a prefix length below 8 gives any address whose leading bits are zero.
/// An address of the neighboring network 1.0.0.0/8 reaches a gateway in its
/// prefix.
#[test]
fn an_address_of_a_zero_network_brings_no_prefix_route_to_a_gateway() {
    let beside =
        |address: &str| format!("{BARE_PRIMARY}3: ens6    inet {address} scope global {LIFETIME}");
    for (address, gateway) in [
        ("192.0.2.1/0", "198.51.100.1"),
        ("10.0.0.5/4", "10.0.1.1"),
        ("0.1.2.3/24", "0.1.2.1"),
    ] {
        let route = format!("10.9.0.0/16 via {gateway} \n");
        assert_eq!(released_batch(&beside(address), &route), None, "{address}");
    }
    assert!(
        released_batch(&beside("1.0.0.5/8"), "10.9.0.0/16 via 1.0.1.1 \n").is_some(),
        "an address of 1.0.0.0/8: refused"
    );
}

/// Binds the fixture's ENI over its one address, its prefix route and
/// `route`, with `text` written to the host file `path`. Returns whether
/// the bind was admitted; a refusal must name `routes` and write nothing.
fn binds_with(path: &str, text: &str, route: &str) -> bool {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    fixture.file(path, text);
    let state = State::listed(format!("{PREFIX_ROUTE}{route} \n"));
    install(&binder.kernel, &state, PRIMARY.to_owned());
    match bind_eni(&binder, None, &FakeMetadata::new()) {
        Err(BindError::Eni(EniError::Unverifiable("routes"))) => {
            assert!(untouched(&binder), "the refused bind wrote");
            false
        }
        bound => {
            bound.expect("the bind");
            true
        }
    }
}

const IPV6_GATEWAYS: [&str; 2] = [
    "10.9.0.0/16 via inet6 fe80::1",
    "10.9.0.0/16 via inet6 2001:db8::1 onlink",
];

/// A route through an IPv6 gateway binds only on a device whose MTU is at
/// least 1280. Below that the kernel holds no IPv6 state for the device and
/// refuses every IPv6 next hop on it, link-local or `onlink`, while a route
/// added at a larger MTU stays listed. Release restores the recorded MTU
/// before it replays the routes.
#[test]
fn a_route_through_an_ipv6_gateway_binds_only_at_an_mtu_that_carries_ipv6() {
    let mtu = "sys/class/net/ens6/mtu";
    for route in IPV6_GATEWAYS {
        assert!(!binds_with(mtu, "1279\n", route), "{route} at 1279: bound");
        assert!(binds_with(mtu, "1280\n", route), "{route} at 1280: refused");
    }
    assert!(
        binds_with(mtu, "1279\n", "10.9.0.0/16 via 10.0.1.1"),
        "an IPv4 gateway at MTU 1279: refused"
    );
}

/// A route through an IPv6 gateway binds only on a host whose new devices
/// start with IPv6 enabled. The returned ENI is a new device, which takes
/// `net.ipv6.conf.default.disable_ipv6`, and the kernel refuses every IPv6
/// next hop on a device with IPv6 disabled. A setting the capture cannot
/// read as `0` refuses, and a route through an IPv4 gateway binds whatever
/// the setting.
#[test]
fn a_route_through_an_ipv6_gateway_binds_only_where_a_new_device_starts_with_ipv6() {
    let setting = "proc/sys/net/ipv6/conf/default/disable_ipv6";
    for route in IPV6_GATEWAYS {
        assert!(!binds_with(setting, "1\n", route), "{route}: bound");
        assert!(!binds_with(setting, "\n", route), "{route}: bound");
        assert!(binds_with(setting, "0\n", route), "{route}: refused");
    }
    assert!(
        binds_with(setting, "1\n", "10.9.0.0/16 via 10.0.1.1"),
        "an IPv4 gateway with IPv6 disabled for new devices: refused"
    );
}

/// Release replays the addresses in listed order: `ip` lists a prefix's
/// primary address before its secondaries, and the address assigned first
/// becomes the primary, whichever is the lower number.
#[test]
fn release_assigns_a_primary_address_before_a_lower_numbered_secondary() {
    let addresses = "3: ens6    inet 10.0.1.9/24 brd 10.0.1.255 scope global ens6\\       valid_lft forever preferred_lft forever\n\
                     3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global secondary ens6\\       valid_lft forever preferred_lft forever\n";
    let routes = "10.0.1.0/24 proto kernel scope link src 10.0.1.9 \n";
    let batch = released_batch(addresses, routes).expect("the bind");
    let assigned: Vec<&str> = batch
        .iter()
        .filter_map(|run| run.strip_prefix("ip addr replace "))
        .collect();
    assert_eq!(
        assigned,
        [
            "10.0.1.9/24 brd 10.0.1.255 dev if6",
            "10.0.1.5/24 brd 10.0.1.255 dev if6"
        ]
    );
}

/// Release orders a recorded route by its scope, listed by name or as a
/// number, and puts a route with no gateway ahead of the routes through
/// gateways. It reads a record written under an earlier admission rule,
/// whose words the capture no longer admits.
#[test]
fn release_orders_a_recorded_route_by_its_scope_whatever_its_other_words() {
    use super::eni::replay_order;
    for (route, order) in [
        ("10.0.9.1 scope host", 0),
        ("10.0.9.1 scope 254", 0),
        ("10.0.9.1 scope host rtt 300ms", 0),
        ("10.0.8.0/24 via 10.0.9.1 scope link", 1),
        ("10.0.8.0/24 via 10.0.9.1 scope 253", 1),
        ("10.0.8.0/24 scope 253 rto_min lock 40ms", 1),
        ("10.0.8.0/24 proto via scope link src 10.0.1.5", 1),
        ("10.0.8.0/24 scope link pervasive", 1),
        ("multicast 239.1.0.0/16 scope link", 1),
        ("10.7.0.0/16", 1),
        ("10.7.0.0/16 scope uplink", 1),
        ("10.0.0.0/8 via 10.0.8.1", 2),
        ("10.0.0.0/8 via 10.0.8.1 proto host", 2),
        ("10.0.0.0/8 via 10.0.8.1 proto scope metric 5", 2),
        ("10.0.0.0/8 via 10.0.8.1 scope uplink", 2),
    ] {
        assert_eq!(replay_order(route), order, "{route}");
    }
}

/// A name that holds a space outside ASCII is one word to `ip` and several
/// to the capture, so an address line with one refuses the bind.
#[test]
fn an_address_line_with_a_space_outside_ascii_refuses_the_bind() {
    let address = "3: ens6    inet 10.0.1.5/24 brd 10.0.1.255 scope global\u{2003}dynamic ens6\\       valid_lft forever preferred_lft forever\n";
    let outcome = round_trip(&State::listed(PREFIX_ROUTE), address.to_owned());
    assert!(
        matches!(
            outcome,
            Err(BindError::Eni(EniError::Unverifiable("addresses")))
        ),
        "{outcome:?}"
    );
}
