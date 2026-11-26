//! The ENI's restoration domain at the bind's two captures and at release:
//! every unrepresented attribute refuses before any ENI driver write, a
//! record releases as it stands, and real network namespaces round-trip a
//! supported configuration through the production capture and restore
//! batch.
//!
//! The scripted cases run on the fake kernel over an IPv6 address table
//! holding the device's link-local address. Each plants one attribute,
//! through the full output of one or two `ip` commands or one more line of
//! that table, at the first capture or between the captures of a combined
//! bind, and judges the driver write log, the fixture's drivers and the
//! record path.
//!
//! The namespace cases run each in a fresh child of the test executable
//! under `unshare --user --map-root-user --net --mount`, with its own
//! sysfs mounted, over dummy and veth interfaces. A case captures the ENI's
//! state with [`Host::net_state`] and the system kernel, recreates the
//! device as a driver rebind does, with the same MAC, default state and
//! possibly another name, replays the record with
//! [`Binder::restore_net_at`] at the interface index the namespace's sysfs
//! gives the recreated device, and compares independent `ip -j` snapshots of
//! the namespace's links, addresses and routes taken before the capture and
//! after the replay. The
//! comparison applies the normalization `normalize` lists to the ENI's
//! entries alone, renewing lifetimes in the snapshot before the capture
//! only; every other interface's entries compare raw.
//! Namespace evidence covers the capture and the replay; PCI and VFIO
//! hardware lie outside it.
//!
//! This module's inventory [`REQUIRED`] is frozen here. Every case has a
//! stable name, a lane and a deadline declared before it runs; a case past
//! its deadline is missing evidence and fails. The QEMU guest binder runs
//! the scheduled exact IDs after its release checks, and reports each
//! completed namespace child separately from its own libtest result.

use std::cell::Cell;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::binder::{BindError, BindRequest, Binder, EniRequest, mappings_path};
use super::binder_tests::{
    ALLOWLISTED, PEERS, bind_eni, neighbors_untouched, new_binder, observed, untouched,
};
use super::eni::{Eni, EniError, NetState};
use super::fixture::{BDF, ENI, ENI_BDF, ENS6_ADDRESS, FakeKernel, FakeMetadata, Fixture, VOLUME};
use super::host::{Fed, Host, Kernel, Started, SysfsKernel};
use super::mappings::{EniBinding, Mappings};
use crate::exact_child::{self, ExactChild};

/// One declared case: its stable name, deadline and run, which panics when
/// a check fails. The run's kind selects the case's lane: a
/// [`Run::Namespace`] case runs in a real user and network namespace by
/// exact ID among the ignored cases, and every other kind runs in the
/// ordinary workspace lane on the fake kernel.
struct Case {
    name: &'static str,
    deadline: Duration,
    run: Run,
}

#[derive(Clone, Copy)]
enum Run {
    /// The attribute planted before the first capture.
    First(&'static Attribute),
    /// The attribute planted between the two captures of a combined bind.
    Between(&'static Attribute),
    Scripted(fn()),
    /// The exact test ID of the namespace case's own test.
    Namespace(&'static str),
}

/// A scripted case finishes within 100 ms in an unoptimized build on a
/// development host; ten seconds leaves a hundredfold margin.
const SCRIPTED: Duration = Duration::from_secs(10);
/// A namespace case, its child's start included, finishes within one
/// second on a development host; thirty seconds leaves room for a loaded
/// runner or guest.
const NAMESPACE: Duration = Duration::from_secs(30);

fn every_namespace() -> Duration {
    CASES
        .iter()
        .filter(|case| matches!(case.run, Run::Namespace(_)))
        .map(|case| case.deadline + exact_child::DRAINS)
        .sum::<Duration>()
        + NAMESPACE
}

/// One approved unrepresented attribute: the fake kernel's full output of
/// each command it plants, the IPv6 address table line it plants beside
/// the device's link-local address, which every case's table holds, and
/// the detail its refusal names.
struct Attribute {
    name: &'static str,
    outputs: &'static [(&'static str, &'static str)],
    inet6: Option<&'static str>,
    detail: &'static str,
}

const SHOW_ADDR: &str = "ip -4 -o addr show dev ens6";
const SHOW_ROUTE: &str = "ip -4 -o route show table all dev ens6";
const SHOW_RULE: &str = "ip -4 -o rule show";
const SHOW_LINK: &str = "ip -6 -o link show dev ens6";
const SHOW_ROUTE6: &str = "ip -6 -o route show table all dev ens6";
const SHOW_RULE6: &str = "ip -6 -o rule show";
const MAIN_ROUTE: &str = "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n";
const DEFAULT_RULES: &str =
    "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";
const LINK_LOCAL: &str = "fe800000000000000000000000000005 03 40 20 80     ens6\n";

const ATTRIBUTES: [Attribute; 13] = [
    Attribute {
        name: "scope",
        outputs: &[(
            SHOW_ADDR,
            "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope link ens6\n",
        )],
        inet6: None,
        detail: "scope",
    },
    Attribute {
        name: "label",
        outputs: &[(
            SHOW_ADDR,
            "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global ens6:x\n",
        )],
        inet6: None,
        detail: "label",
    },
    Attribute {
        name: "peer",
        outputs: &[(
            SHOW_ADDR,
            "3: ens6    inet 10.0.1.5 peer 10.0.1.6/32 scope global ens6\n",
        )],
        inet6: None,
        detail: "peer",
    },
    Attribute {
        name: "deprecated",
        outputs: &[(
            SHOW_ADDR,
            "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global deprecated dynamic ens6\\       valid_lft 3000sec preferred_lft 0sec\n",
        )],
        inet6: None,
        detail: "deprecated",
    },
    Attribute {
        name: "unrecognized-word",
        outputs: &[(
            SHOW_ADDR,
            "3: ens6    inet 10.0.1.5/24 metric 1003 brd 10.0.1.255 scope global tentative ens6\n",
        )],
        inet6: None,
        detail: "addresses",
    },
    Attribute {
        name: "other-table",
        outputs: &[(
            SHOW_ROUTE,
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\n10.8.0.0/16 via 10.0.1.1 table 7\n",
        )],
        inet6: None,
        detail: "routes",
    },
    Attribute {
        name: "local-table-spoof",
        outputs: &[(
            SHOW_ROUTE,
            "10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003\nlocal 10.0.1.9 table local proto kernel scope host src 10.0.1.5\n",
        )],
        inet6: None,
        detail: "routes",
    },
    Attribute {
        name: "rule-address",
        outputs: &[(
            SHOW_RULE,
            "0:\tfrom all lookup local\n32765:\tfrom 10.0.1.5 lookup 7\n32766:\tfrom all lookup main\n",
        )],
        inet6: None,
        detail: "rules",
    },
    Attribute {
        name: "rule-device",
        outputs: &[(
            SHOW_RULE,
            "0:\tfrom all lookup local\n32765:\tfrom all iif ens6 lookup 7\n32766:\tfrom all lookup main\n",
        )],
        inet6: None,
        detail: "rules",
    },
    Attribute {
        name: "rule-altname",
        outputs: &[
            (
                SHOW_LINK,
                "3: ens6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 0a:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\\    altname enp0s6\n",
            ),
            (
                SHOW_RULE,
                "0:\tfrom all lookup local\n32765:\tfrom all oif enp0s6 lookup 7\n32766:\tfrom all lookup main\n",
            ),
        ],
        inet6: None,
        detail: "rules",
    },
    Attribute {
        name: "ipv6-beyond-link-local",
        outputs: &[],
        inet6: Some("fec00000000000000000000000000005 03 40 40 80     ens6\n"),
        detail: "ipv6",
    },
    Attribute {
        name: "ipv6-other-table",
        outputs: &[(
            SHOW_ROUTE6,
            "fe80::/64 proto kernel metric 256 pref medium\n2001:db8::/64 table 7 metric 1024 pref medium\n",
        )],
        inet6: None,
        detail: "routes",
    },
    Attribute {
        name: "ipv6-rule-device",
        outputs: &[(
            SHOW_RULE6,
            "0:\tfrom all lookup local\n32765:\tfrom all iif ens6 lookup 7\n32766:\tfrom all lookup main\n",
        )],
        inet6: None,
        detail: "rules",
    },
];

/// The frozen inventory of the share's cases.
const REQUIRED: [&str; 35] = [
    "first-capture/scope",
    "first-capture/label",
    "first-capture/peer",
    "first-capture/deprecated",
    "first-capture/unrecognized-word",
    "first-capture/other-table",
    "first-capture/local-table-spoof",
    "first-capture/rule-address",
    "first-capture/rule-device",
    "first-capture/rule-altname",
    "first-capture/ipv6-beyond-link-local",
    "first-capture/ipv6-other-table",
    "first-capture/ipv6-rule-device",
    "between-captures/scope",
    "between-captures/label",
    "between-captures/peer",
    "between-captures/deprecated",
    "between-captures/unrecognized-word",
    "between-captures/other-table",
    "between-captures/local-table-spoof",
    "between-captures/rule-address",
    "between-captures/rule-device",
    "between-captures/rule-altname",
    "between-captures/ipv6-beyond-link-local",
    "between-captures/ipv6-other-table",
    "between-captures/ipv6-rule-device",
    "supported/bind-and-release",
    "record/release-restores-what-it-holds",
    "namespace/addresses-and-routes-up",
    "namespace/down-at-the-minimum-mtu",
    "namespace/maximum-mtu",
    "namespace/rename",
    "namespace/partial-batch-and-retry",
    "namespace/label-falsifier",
    "namespace/refusals",
];

const fn scripted(name: &'static str, run: Run) -> Case {
    Case {
        name,
        deadline: SCRIPTED,
        run,
    }
}

const fn namespace(name: &'static str, id: &'static str) -> Case {
    Case {
        name,
        deadline: NAMESPACE,
        run: Run::Namespace(id),
    }
}

const CASES: [Case; 35] = [
    scripted("first-capture/scope", Run::First(&ATTRIBUTES[0])),
    scripted("first-capture/label", Run::First(&ATTRIBUTES[1])),
    scripted("first-capture/peer", Run::First(&ATTRIBUTES[2])),
    scripted("first-capture/deprecated", Run::First(&ATTRIBUTES[3])),
    scripted(
        "first-capture/unrecognized-word",
        Run::First(&ATTRIBUTES[4]),
    ),
    scripted("first-capture/other-table", Run::First(&ATTRIBUTES[5])),
    scripted(
        "first-capture/local-table-spoof",
        Run::First(&ATTRIBUTES[6]),
    ),
    scripted("first-capture/rule-address", Run::First(&ATTRIBUTES[7])),
    scripted("first-capture/rule-device", Run::First(&ATTRIBUTES[8])),
    scripted("first-capture/rule-altname", Run::First(&ATTRIBUTES[9])),
    scripted(
        "first-capture/ipv6-beyond-link-local",
        Run::First(&ATTRIBUTES[10]),
    ),
    scripted(
        "first-capture/ipv6-other-table",
        Run::First(&ATTRIBUTES[11]),
    ),
    scripted(
        "first-capture/ipv6-rule-device",
        Run::First(&ATTRIBUTES[12]),
    ),
    scripted("between-captures/scope", Run::Between(&ATTRIBUTES[0])),
    scripted("between-captures/label", Run::Between(&ATTRIBUTES[1])),
    scripted("between-captures/peer", Run::Between(&ATTRIBUTES[2])),
    scripted("between-captures/deprecated", Run::Between(&ATTRIBUTES[3])),
    scripted(
        "between-captures/unrecognized-word",
        Run::Between(&ATTRIBUTES[4]),
    ),
    scripted("between-captures/other-table", Run::Between(&ATTRIBUTES[5])),
    scripted(
        "between-captures/local-table-spoof",
        Run::Between(&ATTRIBUTES[6]),
    ),
    scripted(
        "between-captures/rule-address",
        Run::Between(&ATTRIBUTES[7]),
    ),
    scripted("between-captures/rule-device", Run::Between(&ATTRIBUTES[8])),
    scripted(
        "between-captures/rule-altname",
        Run::Between(&ATTRIBUTES[9]),
    ),
    scripted(
        "between-captures/ipv6-beyond-link-local",
        Run::Between(&ATTRIBUTES[10]),
    ),
    scripted(
        "between-captures/ipv6-other-table",
        Run::Between(&ATTRIBUTES[11]),
    ),
    scripted(
        "between-captures/ipv6-rule-device",
        Run::Between(&ATTRIBUTES[12]),
    ),
    scripted(
        "supported/bind-and-release",
        Run::Scripted(supported_bind_and_release),
    ),
    scripted(
        "record/release-restores-what-it-holds",
        Run::Scripted(release_restores_what_the_record_holds),
    ),
    namespace(
        "namespace/addresses-and-routes-up",
        "bind::network_tests::a_namespace_round_trips_addresses_and_routes_on_an_up_link",
    ),
    namespace(
        "namespace/down-at-the-minimum-mtu",
        "bind::network_tests::a_namespace_round_trips_a_down_link_at_the_minimum_ipv4_mtu",
    ),
    namespace(
        "namespace/maximum-mtu",
        "bind::network_tests::a_namespace_round_trips_the_maximum_mtu",
    ),
    namespace(
        "namespace/rename",
        "bind::network_tests::a_namespace_round_trips_onto_a_renamed_device",
    ),
    namespace(
        "namespace/partial-batch-and-retry",
        "bind::network_tests::a_namespace_converges_after_a_partial_batch_and_a_retry",
    ),
    namespace(
        "namespace/label-falsifier",
        "bind::network_tests::a_namespace_custom_label_refuses_the_capture",
    ),
    namespace(
        "namespace/refusals",
        "bind::network_tests::a_namespace_refuses_each_unrepresented_attribute",
    ),
];

/// Runs `case` on its own thread, or in its own namespace child, and
/// returns once it passes within its deadline. A failed check fails with
/// its panic; a scripted run past the deadline fails as missing evidence;
/// a namespace child past it fails with its outcome.
fn witness(case: &Case) {
    let run = case.run;
    if let Run::Namespace(id) = run {
        spawn_namespace(id, case.deadline);
        return;
    }
    let (done, finished) = mpsc::channel();
    let worker = thread::spawn(move || {
        match run {
            Run::First(attribute) => refused_at_first_capture(attribute),
            Run::Between(attribute) => refused_between_captures(attribute),
            Run::Scripted(run) => run(),
            Run::Namespace(_) => unreachable!("namespace cases run in a child"),
        }
        let _ = done.send(());
    });
    match finished.recv_timeout(case.deadline) {
        Ok(()) => worker.join().unwrap(),
        Err(RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(worker.join().unwrap_err())
        }
        Err(RecvTimeoutError::Timeout) => panic!(
            "{} gave no witness within {:?}: missing evidence",
            case.name, case.deadline
        ),
    }
}

/// Witnesses every declared namespace case, or every scripted one, and
/// checks that each required case of that kind is among them.
fn witness_kind(namespace: bool) {
    let mut witnessed = Vec::new();
    for case in CASES
        .iter()
        .filter(|case| matches!(case.run, Run::Namespace(_)) == namespace)
    {
        witness(case);
        witnessed.push(case.name);
    }
    for required in REQUIRED
        .iter()
        .filter(|name| name.starts_with("namespace/") == namespace)
    {
        assert!(
            witnessed.contains(required),
            "{required} is required but no case witnessed it"
        );
    }
}

fn run_case(name: &str) {
    witness(
        CASES
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("{name} is a declared case")),
    );
}

/// The inventory is frozen: every required case is declared once, with a
/// deadline; each attribute case's name is its capture and its attribute's
/// name; every namespace case names its own ignored test.
#[test]
fn the_network_case_inventory_is_frozen() {
    let names: Vec<&str> = CASES.iter().map(|case| case.name).collect();
    assert_eq!(names, REQUIRED);
    let source = include_str!("network_tests.rs");
    let scheduled = guest_namespace_cases();
    let mut expected: Vec<&str> = CASES
        .iter()
        .filter_map(|case| match case.run {
            Run::Namespace(id) => Some(id),
            _ => None,
        })
        .collect();
    expected.push("bind::network_tests::every_namespace_replay_case_is_witnessed");
    expected.sort();
    let mut actual: Vec<&str> = scheduled
        .iter()
        .map(|(id, deadline)| {
            assert_eq!(
                *deadline,
                if id.ends_with("every_namespace_replay_case_is_witnessed") {
                    every_namespace()
                } else {
                    NAMESPACE
                }
            );
            assert!(source.contains(&format!(
                "#[test]\n#[ignore = \"{IGNORE}\"]\nfn {}()",
                id.rsplit("::").next().unwrap()
            )));
            id.as_str()
        })
        .collect();
    actual.sort();
    assert_eq!(actual, expected);
    for case in &CASES {
        assert!(!case.deadline.is_zero(), "{}", case.name);
        match case.run {
            Run::First(attribute) => {
                assert_eq!(case.name, format!("first-capture/{}", attribute.name));
            }
            Run::Between(attribute) => {
                assert_eq!(case.name, format!("between-captures/{}", attribute.name));
            }
            Run::Namespace(id) => {
                let name = id.rsplit("::").next().unwrap();
                assert!(
                    source.contains(&format!("#[test]\n#[ignore = \"{IGNORE}\"]\nfn {name}()")),
                    "{id} is an ignored test of this module"
                );
            }
            Run::Scripted(_) => {}
        }
    }
}

#[test]
fn every_attribute_refusal_case_is_witnessed() {
    witness_kind(false);
}

#[test]
fn each_unrepresented_attribute_refuses_at_the_first_capture_before_any_write() {
    for attribute in &ATTRIBUTES {
        run_case(&format!("first-capture/{}", attribute.name));
    }
}

#[test]
fn each_unrepresented_attribute_between_the_captures_rolls_the_controller_back() {
    for attribute in &ATTRIBUTES {
        run_case(&format!("between-captures/{}", attribute.name));
    }
}

#[test]
fn a_supported_configuration_binds_and_releases_its_projection() {
    run_case("supported/bind-and-release");
}

#[test]
fn a_release_restores_what_its_record_holds_under_refused_state() {
    run_case("record/release-restores-what-it-holds");
}

/// A combined bind of the fixture's controller and ENI.
fn bind_both(binder: &Binder<FakeKernel>) -> Result<Mappings, BindError> {
    let metadata = FakeMetadata::new();
    let manifest = Fixture::manifest_of(&binder.host);
    binder.bind(&BindRequest {
        volume: Some(VOLUME),
        eni: Some(EniRequest {
            id: ENI,
            peers: &PEERS,
            metadata: &metadata,
        }),
        posture: ALLOWLISTED,
        wc: &manifest,
        others: &[],
    })
}

fn refused_with(attribute: &Attribute, result: &Result<Mappings, BindError>) -> bool {
    matches!(result, Err(BindError::Eni(EniError::Unverifiable(detail))) if *detail == attribute.detail)
}

/// With `attribute` present at the first capture, a combined bind refuses
/// naming it before any driver write, neighbor change or record.
fn refused_at_first_capture(attribute: &'static Attribute) {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    for (command, output) in attribute.outputs {
        binder
            .kernel
            .outputs
            .borrow_mut()
            .insert((*command).into(), Some((*output).into()));
    }
    let line = attribute.inet6.unwrap_or_default();
    fixture.file("proc/net/if_inet6", &format!("{LINK_LOCAL}{line}"));
    let refused = bind_both(&binder);
    assert!(
        refused_with(attribute, &refused),
        "{}: {refused:?}",
        attribute.name
    );
    assert!(untouched(&binder), "{}", attribute.name);
    assert!(neighbors_untouched(&binder), "{}", attribute.name);
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// With `attribute` appearing between the captures of a combined bind, the
/// second check refuses naming it after the controller moved; rollback
/// restores the controller and removes the record, and every driver write
/// belongs to the controller.
fn refused_between_captures(attribute: &'static Attribute) {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    for (command, output) in attribute.outputs {
        let first = binder.kernel.outputs.borrow().get(*command).cloned();
        binder.kernel.queued.borrow_mut().insert(
            (*command).into(),
            [first.unwrap_or(Some(String::new())), Some((*output).into())].into(),
        );
    }
    let table = fixture.root.join("proc/net/if_inet6");
    fs::write(&table, LINK_LOCAL).unwrap();
    if let Some(line) = attribute.inet6 {
        // The controller's bind to `vfio-pci` falls between the captures of a combined bind.
        binder.kernel.after_write.replace(Some((
            "vfio-pci/bind",
            Box::new(move || fs::write(table, format!("{LINK_LOCAL}{line}")).unwrap()),
        )));
    }
    let refused = bind_both(&binder);
    assert!(
        refused_with(attribute, &refused),
        "{}: {refused:?}",
        attribute.name
    );
    assert!(
        binder
            .kernel
            .writes
            .borrow()
            .iter()
            .any(|(path, _)| path.contains(BDF)),
        "{}: the controller moved before the second capture",
        attribute.name
    );
    assert!(
        binder
            .kernel
            .writes
            .borrow()
            .iter()
            .all(|(path, value)| !path.contains(ENI_BDF) && value != ENI_BDF),
        "{}: every driver write belongs to the controller",
        attribute.name
    );
    assert_eq!(observed(&fixture, BDF), (Some("nvme".into()), None));
    assert_eq!(observed(&fixture, ENI_BDF), (Some("ena".into()), None));
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// A supported configuration binds with its derived words dropped and its
/// lifetimes renewed, and release replays exactly that projection, each
/// command naming the device by its interface index after the link listing
/// that guards that word.
fn supported_bind_and_release() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let mut outputs = binder.kernel.outputs.borrow_mut();
    outputs.insert(
        SHOW_ADDR.into(),
        Some(format!(
            "{ENS6_ADDRESS}3: ens6    inet 10.0.1.6/24 brd 10.0.1.255 scope global secondary noprefixroute ens6\\       valid_lft forever preferred_lft forever\n"
        )),
    );
    outputs.insert(
        SHOW_ROUTE.into(),
        Some(format!(
            "{MAIN_ROUTE}10.9.0.0/16 via 10.0.1.1 metric 50 linkdown\n\
             local 10.0.1.5 table local proto kernel scope host src 10.0.1.5\n\
             broadcast 10.0.1.255 table local proto kernel scope link src 10.0.1.5\n"
        )),
    );
    outputs.insert(SHOW_RULE.into(), Some(DEFAULT_RULES.into()));
    drop(outputs);
    fixture.file("proc/net/if_inet6", LINK_LOCAL);
    let mappings = bind_both(&binder).unwrap();
    let net = &mappings.eni.as_ref().unwrap().net;
    assert_eq!(
        net.addresses,
        [
            "10.0.1.5/24 brd 10.0.1.255 metric 1003",
            "10.0.1.6/24 brd 10.0.1.255 noprefixroute"
        ]
    );
    assert_eq!(
        net.routes,
        [MAIN_ROUTE.trim_end(), "10.9.0.0/16 via 10.0.1.1 metric 50"]
    );
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    let runs = binder.kernel.runs.borrow();
    let replay: Vec<&str> = runs.iter().map(String::as_str).collect();
    assert_eq!(
        replay,
        [
            "ip -o link show",
            "ip link set dev if6 mtu 9001",
            "ip link set dev if6 up",
            "ip addr replace 10.0.1.5/24 brd 10.0.1.255 metric 1003 dev if6",
            "ip addr replace 10.0.1.6/24 brd 10.0.1.255 noprefixroute dev if6",
            "ip route replace 10.0.1.0/24 proto kernel scope link src 10.0.1.5 metric 1003 dev if6",
            "ip route replace 10.9.0.0/16 via 10.0.1.1 metric 50 dev if6",
        ]
    );
}

/// A record releases as it stands: the bound record gains the address
/// `10.0.1.7/24` and the route `10.8.0.0/16`, and each kernel output then
/// shows one attribute admission refuses: the addresses a custom label, the
/// IPv4 routes another table, the IPv4 rules one naming `10.0.1.5`, the IPv6
/// routes another table, and the IPv6 address table a site-local address.
/// Release replays every recorded address and route and shows no address,
/// route or rule; the one listing it runs is the link listing that guards
/// the device's index word.
fn release_restores_what_the_record_holds() {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let mut mappings = bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let net = &mut mappings.eni.as_mut().unwrap().net;
    net.addresses.push("10.0.1.7/24 brd 10.0.1.255".into());
    net.routes.push("10.8.0.0/16 via 10.0.1.1".into());
    mappings
        .write(&mappings_path(&fixture.state_dir()))
        .unwrap();
    for name in ["label", "other-table", "rule-address", "ipv6-other-table"] {
        let attribute = ATTRIBUTES.iter().find(|a| a.name == name).unwrap();
        for (command, output) in attribute.outputs {
            binder
                .kernel
                .outputs
                .borrow_mut()
                .insert((*command).into(), Some((*output).into()));
        }
    }
    fixture.file(
        "proc/net/if_inet6",
        &format!("{LINK_LOCAL}fec00000000000000000000000000005 03 40 40 80     ens6\n"),
    );
    binder.kernel.runs.borrow_mut().clear();
    binder.release(&[]).unwrap();
    let runs = binder.kernel.runs.borrow();
    assert!(
        runs.iter()
            .all(|run| run == "ip -o link show" || !run.contains(" show")),
        "{runs:?}"
    );
    for replayed in [
        "ip addr replace 10.0.1.7/24 brd 10.0.1.255 dev if6",
        "ip route replace 10.8.0.0/16 via 10.0.1.1 dev if6",
    ] {
        assert!(
            runs.iter().any(|run| run == replayed),
            "{replayed}: {runs:?}"
        );
    }
    assert!(!mappings_path(&fixture.state_dir()).exists());
}

/// The ignore reason of every namespace case.
const IGNORE: &str =
    "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount";

/// Runs the QEMU inventory's exact namespace members after the binder's
/// release. Each member completes its own oracle before its guest witness.
pub(super) fn guest_namespace_campaign() {
    for (program, args) in [
        ("ip", &["-Version"][..]),
        ("unshare", &["--version"][..]),
        ("mount", &["--version"][..]),
        ("umount", &["--version"][..]),
    ] {
        run(program, args);
    }
    println!("guest-binder: namespace tools ready");
    for (id, deadline) in guest_namespace_cases() {
        spawn_namespace(&id, deadline);
        println!("guest-binder: namespace {id} passed");
    }
}

fn qemu_inventory() -> Value {
    let inventory: Value =
        serde_json::from_str(include_str!("../../../../scripts/test-inventory.json"))
            .expect("the inventory is JSON");
    inventory["qemu"].clone()
}

/// The scheduled members and deadlines embedded from the lane's inventory.
fn guest_namespace_cases() -> Vec<(String, Duration)> {
    qemu_inventory()["namespace_cases"]
        .as_array()
        .expect("namespace_cases is an array")
        .iter()
        .map(|case| {
            let id = case["id"].as_str().expect("id is a string");
            let seconds = case["deadline_seconds"]
                .as_u64()
                .expect("deadline_seconds is a whole number");
            (id.to_owned(), Duration::from_secs(seconds))
        })
        .collect()
}

/// The lane's run-deadline floor adds `member_drain_seconds` (equal to
/// [`exact_child::DRAINS`]) to each member's deadline.
#[test]
fn the_inventory_s_member_drain_covers_both_output_drains_of_a_member() {
    let seconds = qemu_inventory()["member_drain_seconds"]
        .as_u64()
        .expect("member_drain_seconds is a whole number");
    assert_eq!(Duration::from_secs(seconds), exact_child::DRAINS);
}

/// Missing guest tools fail before namespace success can be reported.
#[test]
fn the_guest_campaign_requires_each_namespace_tool() {
    let id = "bind::network_tests::the_guest_campaign_requires_each_namespace_tool";
    if exact_child::is_child(id) {
        guest_namespace_campaign();
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let tools = ["ip", "unshare", "mount", "umount"];
    let dir = std::env::temp_dir().join(format!("guest-tools-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    for missing in tools {
        for tool in tools {
            let path = dir.join(tool);
            if tool == missing {
                let _ = fs::remove_file(path);
            } else {
                fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let outcome = ExactChild::spawn(id, &[("PATH", dir.to_str().unwrap())])
            .unwrap()
            .finish(Instant::now() + SCRIPTED);
        assert!(
            matches!(&outcome, exact_child::Outcome::Failed { stdout, .. }
                if stdout.iter().all(|line| !line.contains("guest-binder: namespace tools ready"))),
            "{missing}: {outcome:?}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// The arguments of the `unshare` that runs a namespace child: its own
/// user, network and mount namespaces, mapped to root inside.
const UNSHARE: [&str; 4] = ["--user", "--map-root-user", "--net", "--mount"];

/// The report a namespace child writes once its case's checks passed.
fn passed(id: &str) -> String {
    format!("passed {id}")
}

/// Runs namespace case `id` in a fresh child under `unshare` [`UNSHARE`] and panics
/// unless that child enters and passes it before `deadline`.
fn spawn_namespace(id: &str, deadline: Duration) {
    let outcome = ExactChild::spawn_under("unshare", &UNSHARE, id, &[])
        .unwrap_or_else(|error| panic!("spawn {id} under unshare: {error}"))
        .finish(Instant::now() + deadline);
    assert!(
        exact_child::credited(id, &outcome)
            && matches!(&outcome, exact_child::Outcome::Completed { reports } if reports.contains(&passed(id))),
        "{id} in a namespace child: {outcome:?}"
    );
}

/// Runs `body` as namespace case `id`: inside the child it mounts the
/// namespace's sysfs and runs `body`; elsewhere it spawns that child.
fn in_namespace(id: &str, body: fn(&Namespace)) {
    if !exact_child::is_child(id) {
        spawn_namespace(id, NAMESPACE);
        return;
    }
    exact_child::report(&exact_child::entered(id));
    let namespace = Namespace::enter();
    body(&namespace);
    exact_child::report(&passed(id));
}

/// The child's namespace: its sysfs mount and the host that reads it.
struct Namespace {
    sys: PathBuf,
    host: Host,
}

impl Namespace {
    fn enter() -> Self {
        let sys = std::env::temp_dir().join(format!("bind-namespace-sys-{}", std::process::id()));
        fs::create_dir_all(&sys).unwrap();
        run("mount", &["-t", "sysfs", "sysfs", sys.to_str().unwrap()]);
        assert!(
            sys.join("class/net/lo").exists(),
            "the namespace's sysfs lists its own devices"
        );
        let mut host = Host::system();
        host.sys = sys.clone();
        Self { sys, host }
    }

    /// The ENI's network state through the production capture and the
    /// system kernel. The capture refuses `Unverifiable("name")` when the
    /// host's uevent counter moves across it, and that one counter counts
    /// the devices the other namespace cases create beside this one. Such a
    /// refusal says nothing about this namespace, so the capture is taken
    /// again until one ends under a still counter or the case's deadline
    /// passes; every other result returns as the capture gave it.
    fn capture(&self, netdev: &str) -> Result<NetState, EniError> {
        let until = Instant::now() + NAMESPACE;
        loop {
            match self.host.net_state(&SysfsKernel, netdev) {
                Err(EniError::Unverifiable("name")) if Instant::now() < until => {}
                result => return result,
            }
        }
    }

    /// Replays `net` onto `netdev` with the production restore batch, under
    /// `kernel`, at the interface index the namespace's sysfs gives `netdev`.
    /// A dummy device has no PCI function, so the case reads the index
    /// itself where release reads it under the recorded function.
    fn replay<K: Kernel>(&self, kernel: K, net: &NetState, netdev: &str) -> Result<(), BindError> {
        let binder = Binder {
            host: self.host.clone(),
            kernel,
            state_dir: self.sys.clone(),
        };
        let index = Host::read(&self.host.sys.join("class/net").join(netdev).join("ifindex"))
            .and_then(|index| index.parse().ok())
            .unwrap_or_else(|| panic!("the namespace's sysfs gives {netdev} an interface index"));
        binder.restore_net_at(&binding(net.clone()), index)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.sys).status();
        let _ = fs::remove_dir(&self.sys);
    }
}

/// A record whose network state is `net`; replay reads that state and the
/// recorded PCI address.
fn binding(net: NetState) -> EniBinding {
    EniBinding {
        eni: Eni {
            id: ENI.into(),
            mac: [0x0a, 0x11, 0x22, 0x33, 0x44, 0x55],
            ipv4: Ipv4Addr::new(10, 0, 1, 5),
            subnet: "subnet-0".into(),
            cidr: (Ipv4Addr::new(10, 0, 1, 0), 24),
            device_number: 1,
            network_card: 0,
            netdev: "d0".into(),
            bdf: ENI_BDF.into(),
        },
        original_driver: "ena".into(),
        original_override: None,
        net,
        next_hops: Vec::new(),
    }
}

/// Runs `program` with `args` and returns its standard output, panicking on
/// a failed run.
fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Runs each line of `script` as one `ip` command.
fn ip(script: &str) {
    for line in script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        run("ip", &line.split_whitespace().collect::<Vec<_>>());
    }
}

/// The ENI's MAC in every namespace case, kept across its recreation as a
/// permanent MAC is.
const MAC: &str = "0a:11:22:33:44:55";

/// An unrelated dummy with an address and a route, and a veth pair with an
/// address on `v0`, which every comparison requires unchanged. With
/// `addrgenmode none` the veths carry IPv4 state alone, so duplicate address
/// detection and its late routes leave each snapshot settled.
const OTHERS: &str = "
    link add o0 type dummy
    link set o0 up
    addr add 10.5.0.1/24 dev o0
    route add 10.6.0.0/16 via 10.5.0.2 dev o0
    link add v0 type veth peer name v1
    link set v0 addrgenmode none
    link set v1 addrgenmode none
    link set v0 up
    link set v1 up
    addr add 10.7.0.1/24 dev v0
";

/// Waits until both veths of [`OTHERS`] report their operational state
/// `up`, within the case's deadline, so the first snapshot reads them
/// settled.
fn await_others(namespace: &Namespace) {
    let until = Instant::now() + NAMESPACE;
    let up = |name: &str| {
        fs::read_to_string(namespace.sys.join("class/net").join(name).join("operstate"))
            .is_ok_and(|state| state.trim() == "up")
    };
    while !(up("v0") && up("v1")) {
        assert!(
            Instant::now() < until,
            "the veths reach `up` within the deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Recreates the ENI as a driver rebind does: the device `from` goes away
/// and `to` appears with the same MAC, MTU 1500, the link down and an empty
/// address and route list.
fn rebind(from: &str, to: &str) {
    ip(&format!(
        "link del {from}\nlink add {to} address {MAC} mtu 1500 type dummy"
    ));
}

/// Independent snapshots of the namespace's links, addresses and routes
/// from `ip -j`, normalized by [`normalize`] with the ENI named `eni`.
fn snapshot(eni: &str, before: bool) -> Vec<String> {
    let mut entries = Vec::new();
    for (kind, args) in [
        ("link", &["-j", "link", "show"][..]),
        ("addr", &["-j", "addr", "show"]),
        ("route4", &["-j", "-4", "route", "show", "table", "all"]),
        ("route6", &["-j", "-6", "route", "show", "table", "all"]),
    ] {
        let output = run("ip", args);
        let Ok(Value::Array(items)) = serde_json::from_str(&output) else {
            panic!("ip {args:?} prints a JSON array: {output}");
        };
        for item in items {
            entries.push(format!("{kind} {}", normalize(item, eni, before)));
        }
    }
    entries.sort();
    entries
}

/// `item` with the ENI's entries normalized; every other entry compares
/// raw. The normalization is exactly this list:
///
/// - Order: links and addresses compare by interface, and an interface's
///   addresses and the namespace's routes compare as multisets.
/// - Renamed identity: the ENI's name before and after replay are one name
///   in `ifname`, `label` and route `dev`, and its `ifindex` is dropped,
///   since a rebind creates a new device.
/// - Carrier: the link's `operstate` and `LOWER_UP` flag and the routes'
///   `linkdown` and `dead` flags are dropped, since the kernel derives them.
/// - Lifetimes: replay assigns forever lifetimes, so in the snapshot
///   `before` the capture every IPv4 address's lifetimes read as forever
///   and its `dynamic` flag is dropped; the snapshot after the replay keeps
///   the kernel's lifetimes, so a replay that assigns a finite lifetime
///   differs. The kernel derives `secondary` from address order, which
///   replay keeps, so it compares as printed.
fn normalize(mut item: Value, eni: &str, before: bool) -> Value {
    let Value::Object(fields) = &mut item else {
        panic!("ip prints objects");
    };
    let ours = ["ifname", "dev"]
        .iter()
        .any(|key| fields.get(*key).and_then(Value::as_str) == Some(eni));
    if !ours {
        return item;
    }
    fields.retain(|key, _| !matches!(key.as_str(), "ifindex" | "operstate"));
    for (key, value) in fields.iter_mut() {
        match (key.as_str(), value) {
            ("ifname" | "dev", value) => *value = Value::from("ENI"),
            ("flags", Value::Array(flags)) => flags
                .retain(|flag| !matches!(flag.as_str(), Some("LOWER_UP" | "linkdown" | "dead"))),
            ("addr_info", Value::Array(addresses)) => {
                for address in addresses.iter_mut() {
                    *address = renew(address.take(), eni, before);
                }
                addresses.sort_by_key(Value::to_string);
            }
            _ => {}
        }
    }
    item
}

/// One `addr_info` entry with the ENI's label renamed and, `before` the
/// capture and for IPv4, its lifetimes renewed to forever and its `dynamic`
/// flag dropped.
fn renew(mut address: Value, eni: &str, before: bool) -> Value {
    let Value::Object(fields) = &mut address else {
        panic!("addr_info holds objects");
    };
    let inet = before && fields.get("family").and_then(Value::as_str) == Some("inet");
    if inet {
        fields.remove("dynamic");
    }
    for (key, value) in fields.iter_mut() {
        match key.as_str() {
            "label" if value.as_str() == Some(eni) => *value = Value::from("ENI"),
            "valid_life_time" | "preferred_life_time" if inet => *value = Value::from(u32::MAX),
            _ => {}
        }
    }
    address
}

/// Captures the ENI `d0` after `setup`, rebinds it as `renamed`, replays
/// the capture and requires the normalized snapshots equal, returning the
/// capture.
fn round_trip(namespace: &Namespace, setup: &str, renamed: &str) -> NetState {
    ip(OTHERS);
    await_others(namespace);
    ip(&format!("link add d0 address {MAC} type dummy\n{setup}"));
    let before = snapshot("d0", true);
    let net = namespace.capture("d0").unwrap();
    rebind("d0", renamed);
    namespace.replay(SysfsKernel, &net, renamed).unwrap();
    assert_eq!(before, snapshot(renamed, false));
    net
}

/// Several addresses in two subnets, primary and secondary, with `metric`,
/// `noprefixroute`, a finite lifetime and a broadcast, and several routes,
/// round-trip on an up link at MTU 9001. Three of the routes form a chain
/// the kernel lists in the reverse of the order release replays: a route
/// through a gateway that only a link-scope route reaches, that link-scope
/// route, through a gateway that only a host-scope route reaches, and the
/// host-scope route. Two more carry metrics release replays.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_round_trips_addresses_and_routes_on_an_up_link() {
    in_namespace(
        "bind::network_tests::a_namespace_round_trips_addresses_and_routes_on_an_up_link",
        |namespace| {
            let net = round_trip(
                namespace,
                "link set d0 mtu 9001
                 link set d0 up
                 addr add 10.0.1.5/24 brd + metric 1003 dev d0 valid_lft 3000 preferred_lft 2000
                 addr add 10.0.1.6/24 dev d0
                 addr add 10.0.2.5/24 noprefixroute dev d0
                 route add 10.9.0.0/16 via 10.0.1.1 dev d0
                 route add 10.10.0.0/16 via 10.0.1.1 metric 50 dev d0
                 route add 10.11.0.0/16 dev d0 scope link
                 route add 10.0.9.1 dev d0 scope host
                 route add 10.0.8.0/24 via 10.0.9.1 dev d0 scope link
                 route add 10.0.0.0/9 via 10.0.8.1 dev d0
                 route add 10.12.0.0/16 via 10.0.1.1 dev d0 mtu lock 1400 advmss 1360 window 3000 initcwnd 10 hoplimit 60
                 route add 10.13.0.0/16 via 10.0.1.1 dev d0 ssthresh 20 cwnd 10 initrwnd 20 reordering 5 quickack 1 features ecn",
                "d0",
            );
            assert_eq!(net.addresses.len(), 3);
            assert!(net.routes.len() >= 9, "{:?}", net.routes);
            for metric in [
                "mtu lock 1400",
                "advmss 1360",
                "window 3000",
                "initcwnd 10",
                "hoplimit 60",
                "ssthresh 20",
                "cwnd 10",
                "initrwnd 20",
                "reordering 5",
                "quickack 1",
                "features ecn",
            ] {
                assert!(
                    net.routes.iter().any(|route| route.contains(metric)),
                    "{metric} is not recorded: {:?}",
                    net.routes
                );
            }
            let at = |route: &str| {
                net.routes
                    .iter()
                    .position(|listed| listed.starts_with(route))
                    .unwrap_or_else(|| panic!("{route} is not recorded: {:?}", net.routes))
            };
            assert!(
                at("10.0.0.0/9 via 10.0.8.1") < at("10.0.8.0/24 via 10.0.9.1")
                    && at("10.0.8.0/24 via 10.0.9.1") < at("10.0.9.1 scope host"),
                "the listing puts the route through each gateway ahead of the gateway's route: {:?}",
                net.routes
            );
        },
    );
}

/// A down link at MTU 68, the IPv4 minimum, which also disables IPv6 on
/// the device, round-trips with its addresses.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_round_trips_a_down_link_at_the_minimum_ipv4_mtu() {
    in_namespace(
        "bind::network_tests::a_namespace_round_trips_a_down_link_at_the_minimum_ipv4_mtu",
        |namespace| {
            let net = round_trip(
                namespace,
                "link set d0 mtu 68
                 addr add 10.0.1.5/24 brd + dev d0
                 addr add 10.0.3.5/24 metric 7 dev d0",
                "d0",
            );
            assert!(!net.up);
            assert_eq!(net.mtu.get(), 68);
        },
    );
}

/// MTU 65535 round-trips on an up link.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_round_trips_the_maximum_mtu() {
    in_namespace(
        "bind::network_tests::a_namespace_round_trips_the_maximum_mtu",
        |namespace| {
            let net = round_trip(
                namespace,
                "link set d0 mtu 65535
                 link set d0 up
                 addr add 10.0.1.5/24 dev d0",
                "d0",
            );
            assert_eq!(net.mtu.get(), 65535);
        },
    );
}

/// The device returns under an enumerated name, and the replay onto it
/// restores the state, its label renamed with it.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_round_trips_onto_a_renamed_device() {
    in_namespace(
        "bind::network_tests::a_namespace_round_trips_onto_a_renamed_device",
        |namespace| {
            round_trip(
                namespace,
                "link set d0 up
                 addr add 10.0.1.5/24 brd + metric 1003 dev d0
                 route add 10.9.0.0/16 via 10.0.1.1 dev d0",
                "eth0",
            );
        },
    );
}

/// A kernel whose next `ip -batch -` applies only its first `keep`
/// commands and then fails, as `ip` stops at a failed command; every other
/// call goes to the system kernel.
struct Partial {
    real: SysfsKernel,
    keep: Cell<Option<usize>>,
}

impl Partial {
    fn keeping(keep: usize) -> Self {
        Self {
            real: SysfsKernel,
            keep: Cell::new(Some(keep)),
        }
    }
}

struct Cut<'k> {
    started: Box<dyn Started + 'k>,
    keep: usize,
}

impl Started for Cut<'_> {
    fn feed<'s>(self: Box<Self>, input: &str) -> Box<dyn Fed + 's>
    where
        Self: 's,
    {
        let prefix: String =
            input
                .lines()
                .take(self.keep)
                .fold(String::new(), |mut prefix, line| {
                    let _ = writeln!(prefix, "{line}");
                    prefix
                });
        Box::new(Failing(self.started.feed(&prefix)))
    }
}

/// A batch fed its kept commands, which fails once they have run.
struct Failing<'k>(Box<dyn Fed + 'k>);

impl Fed for Failing<'_> {
    fn finish(self: Box<Self>) -> io::Result<String> {
        self.0.finish()?;
        Err(io::Error::other("the batch stopped at a failed command"))
    }
}

impl Kernel for Partial {
    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        self.real.write(path, value)
    }

    fn start<'k>(&'k self, program: &str, args: &[&str]) -> io::Result<Box<dyn Started + 'k>> {
        let started = self.real.start(program, args)?;
        // The link listing that precedes a batch leaves the cut in place.
        if !matches!(args, ["-batch", "-"]) {
            return Ok(started);
        }
        match self.keep.take() {
            Some(keep) => Ok(Box::new(Cut { started, keep })),
            None => Ok(started),
        }
    }

    fn solicit(&self, netdev: &str, hop: Ipv4Addr) -> io::Result<()> {
        self.real.solicit(netdev, hop)
    }

    fn settle(&self, interval: Duration) {
        self.real.settle(interval);
    }

    fn now(&self) -> Instant {
        self.real.now()
    }

    fn open_group(&self, path: &Path) -> io::Result<fs::File> {
        self.real.open_group(path)
    }

    fn group_status(&self, group: &fs::File) -> io::Result<u32> {
        self.real.group_status(group)
    }
}

/// A batch that stops after the MTU under the enumerated name, a rename by
/// udev, and a rerun under the new name converge; a batch that stops after
/// the first address and a rerun under the same name converge too.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_converges_after_a_partial_batch_and_a_retry() {
    in_namespace(
        "bind::network_tests::a_namespace_converges_after_a_partial_batch_and_a_retry",
        |namespace| {
            ip(OTHERS);
            await_others(namespace);
            ip(&format!(
                "link add d0 address {MAC} type dummy
                 link set d0 mtu 9001
                 link set d0 up
                 addr add 10.0.1.5/24 brd + metric 1003 dev d0
                 addr add 10.0.2.5/24 noprefixroute dev d0
                 route add 10.9.0.0/16 via 10.0.1.1 dev d0"
            ));
            let before = snapshot("d0", true);
            let net = namespace.capture("d0").unwrap();
            rebind("d0", "eth0");
            assert!(namespace.replay(Partial::keeping(1), &net, "eth0").is_err());
            assert_eq!(
                fs::read_to_string(namespace.sys.join("class/net/eth0/mtu")).unwrap(),
                "9001\n",
                "the batch's prefix applied"
            );
            let flags = fs::read_to_string(namespace.sys.join("class/net/eth0/flags")).unwrap();
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
            assert_eq!(flags & 1, 0, "the link stays down after the MTU alone");
            assert_eq!(run("ip", &["-4", "-o", "addr", "show", "dev", "eth0"]), "");
            ip("link set dev eth0 name ens6");
            namespace.replay(SysfsKernel, &net, "ens6").unwrap();
            assert_eq!(before, snapshot("ens6", false));
            rebind("ens6", "ens6");
            assert!(namespace.replay(Partial::keeping(3), &net, "ens6").is_err());
            assert_eq!(
                run("ip", &["-4", "-o", "addr", "show", "dev", "ens6"])
                    .lines()
                    .count(),
                1,
                "the batch's prefix assigned its first address alone"
            );
            namespace.replay(SysfsKernel, &net, "ens6").unwrap();
            assert_eq!(before, snapshot("ens6", false));
        },
    );
}

/// An address labeled `d0:x`, which the capture's projection would drop,
/// refuses the capture, while the independent snapshot shows the kernel
/// holding that label; the same address with the device's own label is
/// captured.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_custom_label_refuses_the_capture() {
    in_namespace(
        "bind::network_tests::a_namespace_custom_label_refuses_the_capture",
        |namespace| {
            ip(&format!(
                "link add d0 address {MAC} type dummy
                 link set d0 up
                 addr add 10.0.1.5/24 dev d0
                 addr add 10.0.1.7/24 dev d0 label d0:x"
            ));
            assert!(
                run("ip", &["-j", "addr", "show", "dev", "d0"]).contains("\"label\":\"d0:x\""),
                "the kernel holds the label"
            );
            assert_eq!(
                namespace.capture("d0"),
                Err(EniError::Unverifiable("label"))
            );
            ip("addr del 10.0.1.7/24 dev d0\naddr add 10.0.1.7/24 dev d0");
            assert_eq!(namespace.capture("d0").unwrap().addresses.len(), 2);
        },
    );
}

/// Each unrepresented attribute set in the real kernel refuses the capture
/// with the detail that names it, IPv6 routes and rules and rules naming
/// the device's altname included, and removing it admits the device again.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn a_namespace_refuses_each_unrepresented_attribute() {
    in_namespace(
        "bind::network_tests::a_namespace_refuses_each_unrepresented_attribute",
        |namespace| {
            ip(&format!(
                "link add d0 address {MAC} type dummy
                 link property add dev d0 altname eniA
                 link set d0 up
                 addr add 10.0.1.5/24 dev d0"
            ));
            let first = namespace.capture("d0");
            assert!(first.is_ok(), "{first:?}");
            ip("nexthop add id 9 via 10.0.1.1 dev d0
                link set d0 alias uplink
                link set d0 group 7
                link set d0 txqueuelen 500");
            assert_eq!(
                namespace.capture("d0"),
                first,
                "an unreferenced nexthop object, an alias, a group and a queue length"
            );
            ip("nexthop del id 9");
            // These host routes belong to no device, and the last goes through another device's nexthop object.
            ip("route add blackhole 10.99.0.0/16
                route add unreachable 10.98.0.0/16 metric 5
                route add prohibit 10.97.0.0/16 table 7
                link add d1 type dummy
                link set d1 up
                addr add 10.1.1.5/24 dev d1
                nexthop add id 8 via 10.1.1.1 dev d1
                route add blackhole 10.95.0.0/16 nhid 8");
            assert_eq!(
                namespace.capture("d0"),
                first,
                "host routes of a device-less type, in main and in another table"
            );
            ip("route del blackhole 10.99.0.0/16
                route del unreachable 10.98.0.0/16 metric 5
                route del prohibit 10.97.0.0/16 table 7
                route del 10.95.0.0/16
                nexthop del id 8
                link del d1");
            // A device created after this write starts with IPv6 disabled, as the returned ENI would, and
            // the kernel takes no IPv6 gateway on it. `d0` keeps IPv6 and the route.
            let new_devices = "/proc/sys/net/ipv6/conf/default/disable_ipv6";
            ip("route add 10.22.0.0/16 via inet6 fe80::1 dev d0");
            assert!(namespace.capture("d0").is_ok(), "an IPv6 gateway");
            fs::write(new_devices, "1").unwrap();
            assert_eq!(
                namespace.capture("d0"),
                Err(EniError::Unverifiable("routes")),
                "an IPv6 gateway where a new device starts with IPv6 disabled"
            );
            ip("link add d2 type dummy\nlink set d2 up");
            assert!(
                !Command::new("ip")
                    .args("route add 10.23.0.0/16 via inet6 fe80::1 dev d2".split(' '))
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "the kernel took an IPv6 gateway on a device with IPv6 disabled"
            );
            ip("link del d2");
            fs::write(new_devices, "0").unwrap();
            ip("route del 10.22.0.0/16");
            assert!(namespace.capture("d0").is_ok());
            let cases = [
                (
                    "addr add 10.0.3.5/24 scope link dev d0",
                    "addr del 10.0.3.5/24 dev d0",
                    "scope",
                ),
                (
                    "addr add 10.0.2.5 peer 10.0.2.6/32 dev d0",
                    "addr del 10.0.2.5 peer 10.0.2.6/32 dev d0",
                    "peer",
                ),
                (
                    "addr add 10.0.4.5/24 dev d0 valid_lft 300 preferred_lft 0",
                    "addr del 10.0.4.5/24 dev d0",
                    "deprecated",
                ),
                (
                    "route add 10.8.0.0/16 via 10.0.1.1 dev d0 table 7",
                    "route del 10.8.0.0/16 table 7",
                    "routes",
                ),
                (
                    "route add local 10.0.1.5 dev d0 table local proto kernel scope host src 10.0.1.5 metric 7",
                    "route del local 10.0.1.5 dev d0 table local metric 7",
                    "routes",
                ),
                (
                    "route add 10.8.0.0/16 via 10.0.1.1 dev d0 rto_min 40ms",
                    "route del 10.8.0.0/16",
                    "routes",
                ),
                (
                    "route add 10.8.0.0/16 via 10.0.1.1 dev d0 rtt 300ms",
                    "route del 10.8.0.0/16",
                    "routes",
                ),
                (
                    "route add local 10.5.5.5 dev d0 table main",
                    "route del local 10.5.5.5 dev d0 table main",
                    "routes",
                ),
                (
                    "route add 10.7.0.0/16 dev d0 scope global",
                    "route del 10.7.0.0/16",
                    "routes",
                ),
                (
                    "route add 10.9.0.0/16 via 10.0.1.1 dev d0\nroute append 10.9.0.0/16 via 10.0.1.2 dev d0",
                    "route del 10.9.0.0/16 via 10.0.1.2 dev d0\nroute del 10.9.0.0/16",
                    "routes",
                ),
                (
                    "route add blackhole 10.8.0.0/16 metric 5\nroute append 10.8.0.0/16 via 10.0.1.1 dev d0 metric 5",
                    "route del 10.8.0.0/16 via 10.0.1.1 dev d0 metric 5\nroute del blackhole 10.8.0.0/16 metric 5",
                    "routes",
                ),
                (
                    "route add blackhole 10.96.0.0/16 src 10.0.1.5",
                    "route del blackhole 10.96.0.0/16",
                    "routes",
                ),
                (
                    "addr add 10.0.5.5/24 dev d0\nroute add 10.20.0.0/16 via 10.0.5.1 dev d0\naddr del 10.0.5.5/24 dev d0",
                    "route del 10.20.0.0/16",
                    "routes",
                ),
                (
                    "addr add 10.0.6.5/24 noprefixroute dev d0\naddr add 10.0.6.6/24 dev d0\nroute add 10.0.6.0/24 dev d0 scope link\nroute add 10.21.0.0/16 via 10.0.6.1 dev d0\nroute del 10.0.6.0/24 dev d0",
                    "route del 10.21.0.0/16\naddr del 10.0.6.6/24 dev d0\naddr del 10.0.6.5/24 dev d0",
                    "routes",
                ),
                (
                    "link add d3 type dummy\nlink set d3 up\naddr add 10.3.1.5/24 dev d3\nroute add 10.30.0.0/16 via 10.0.1.1 dev d0 metric 7\nroute append 10.30.0.0/16 via 10.3.1.1 dev d3 metric 7",
                    "route del 10.30.0.0/16 via 10.0.1.1 dev d0 metric 7\nlink del d3",
                    "routes",
                ),
                (
                    "link add d3 type dummy\nlink set d3 up\naddr add 10.3.1.5/24 dev d3\nroute add 10.31.0.0/16 via 10.3.1.1 dev d3 src 10.0.1.5",
                    "link del d3",
                    "routes",
                ),
                (
                    "link add d3 type dummy\nlink set d3 up\naddr add 10.0.1.9/24 dev d3",
                    "link del d3",
                    "routes",
                ),
                (
                    "addr add 192.0.2.1/0 dev d0\nroute add 198.51.100.0/24 dev d0 scope link\nroute add 10.24.0.0/16 via 198.51.100.1 dev d0\nroute del 198.51.100.0/24 dev d0",
                    "route del 10.24.0.0/16\naddr del 192.0.2.1/0 dev d0",
                    "routes",
                ),
                (
                    "route add 10.22.0.0/16 via inet6 fe80::1 dev d0\nlink set d0 mtu 1279",
                    "route del 10.22.0.0/16\nlink set d0 mtu 1500",
                    "routes",
                ),
                (
                    "rule add from 10.0.1.5 lookup 7",
                    "rule del from 10.0.1.5 lookup 7",
                    "rules",
                ),
                (
                    "rule add iif d0 lookup 7",
                    "rule del iif d0 lookup 7",
                    "rules",
                ),
                (
                    "-6 addr add 2001:db8::5/64 dev d0 nodad",
                    "-6 addr del 2001:db8::5/64 dev d0",
                    "ipv6",
                ),
                (
                    "-6 addr add fe80::5/64 dev d0 nodad",
                    "-6 addr del fe80::5/64 dev d0",
                    "ipv6",
                ),
                (
                    "-6 route add 2001:db8::/64 dev d0 table 7",
                    "-6 route del 2001:db8::/64 dev d0 table 7",
                    "routes",
                ),
                (
                    "-6 route add 2001:db8:1::/64 dev d0",
                    "-6 route del 2001:db8:1::/64 dev d0",
                    "routes",
                ),
                (
                    "-6 route add 2001:db8::/128 dev d0",
                    "-6 route del 2001:db8::/128 dev d0",
                    "routes",
                ),
                (
                    "nexthop add id 5 via 10.0.1.1 dev d0\nroute add 10.5.0.0/16 nhid 5",
                    "route del 10.5.0.0/16\nnexthop del id 5",
                    "routes",
                ),
                (
                    "-6 rule add iif d0 lookup 7",
                    "-6 rule del iif d0 lookup 7",
                    "rules",
                ),
                (
                    "rule add oif eniA lookup 7",
                    "rule del oif eniA lookup 7",
                    "rules",
                ),
                (
                    "-6 rule add iif eniA lookup 7",
                    "-6 rule del iif eniA lookup 7",
                    "rules",
                ),
            ];
            for (add, remove, detail) in cases {
                ip(add);
                assert_eq!(
                    namespace.capture("d0"),
                    Err(EniError::Unverifiable(detail)),
                    "{add}"
                );
                ip(remove);
                assert!(namespace.capture("d0").is_ok(), "{remove}");
            }
        },
    );
}

/// Runs every namespace case of the inventory, each in its own child.
#[test]
#[ignore = "needs the disposable QEMU guest namespace campaign with ip, unshare, mount and umount"]
fn every_namespace_replay_case_is_witnessed() {
    let id = "bind::network_tests::every_namespace_replay_case_is_witnessed";
    if exact_child::is_child(id) {
        exact_child::report(&exact_child::entered(id));
        witness_kind(true);
        exact_child::report(&passed(id));
    } else {
        spawn_namespace(id, every_namespace());
    }
}
