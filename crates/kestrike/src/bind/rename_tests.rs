//! Release's network batch beside a second device.
//!
//! The property, from the owner invariant in `bind/mod.rs` and the
//! documentation of `Binder::restore_net_as` and `Binder::restore_net_at`:
//! release restores only what its
//! own directory records, so every batch command lands on the recorded ENI,
//! whichever device holds the ENI's earlier name or the word `if<index>`.
//!
//! The kernel here finds a device by the name or altname it has and then by
//! its index, as `ip` does, and keeps what the commands set on each device.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use super::binder::{BindError, Binder, mappings_path};
use super::binder_tests::{bind_eni, new_binder};
use super::eni::NetState;
use super::fixture::{FakeKernel, FakeMetadata, Fixture, make_fifo, release};
use super::host::{Kernel, Started};

/// What batch commands set on the device, whatever its name was.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Device {
    mtu: Option<String>,
    up: Option<bool>,
    addresses: BTreeSet<String>,
    routes: BTreeSet<String>,
}

impl Device {
    /// The state a record's batch leaves on a device.
    fn recorded(net: &NetState) -> Self {
        let words = |text: &String| text.split_whitespace().collect::<Vec<_>>().join(" ");
        Self {
            mtu: Some(net.mtu.to_string()),
            up: Some(net.up),
            addresses: net.addresses.iter().map(words).collect(),
            routes: net.routes.iter().map(words).collect(),
        }
    }

    /// Applies one batch command, with its device already checked.
    ///
    /// # Panics
    ///
    /// On a command that is no link, address or route command.
    fn apply(&mut self, words: &[&str]) {
        match *words {
            ["link", "set", "dev", _, "mtu", mtu] => self.mtu = Some(mtu.to_owned()),
            ["link", "set", "dev", _, "up"] => self.up = Some(true),
            ["link", "set", "dev", _, "down"] => self.up = Some(false),
            ["addr", "replace", ref rest @ .., "dev", _] => {
                self.addresses.insert(rest.join(" "));
            }
            ["route", "replace", ref rest @ .., "dev", _] => {
                self.routes.insert(rest.join(" "));
            }
            _ => panic!("a release command outside the ENI's network state: {words:?}"),
        }
    }
}

/// The other owner's dataplane device, which returns to `ena` while this
/// owner's release runs.
const OTHER_BDF: &str = "0000:00:07.0";
const OTHER_MAC: &str = "0a:77:77:77:77:77";

/// A [`FakeKernel`] under which a second device takes the ENI's vacated
/// name. The ENI returns as `eth0`. Before the batch command at `at`, udev
/// renames the ENI to `enp0s1` and the other owner's device, returning to
/// `ena`, is enumerated as `eth0`. Each command lands on the device that holds the name it gives at that
/// moment or holds it as an altname and, when no device holds it, on the
/// device whose interface index an `if<N>` word gives, the order in which
/// `ip` resolves a device.
struct Reuse<'f> {
    inner: FakeKernel,
    fixture: &'f Fixture,
    at: Option<usize>,
    /// The ENI's name and, once it has returned, the other device's.
    names: RefCell<(String, Option<String>)>,
    /// The other device's altname, which `ip -o link show` lists.
    altname: Option<&'static str>,
    /// What the batches set on the ENI and on the other device.
    devices: RefCell<[Device; 2]>,
}

/// The interface indexes of the ENI and of the other device.
const INDEXES: [u32; 2] = [6, 7];

impl Reuse<'_> {
    fn reuse(&self) {
        let net = self.fixture.host.sys.join("class/net");
        let mut names = self.names.borrow_mut();
        fs::rename(net.join(&names.0), net.join("enp0s1")).unwrap();
        self.fixture.netdev(&names.0, OTHER_BDF, OTHER_MAC, 0x1003);
        names.1 = Some(std::mem::replace(&mut names.0, "enp0s1".to_owned()));
    }

    fn batch(&self, input: &str) -> io::Result<String> {
        for (index, line) in input.lines().enumerate() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let named = words[words.iter().position(|word| *word == "dev").unwrap() + 1];
            if self.at == Some(index) && self.names.borrow().1.is_none() {
                self.reuse();
            }
            let names = self.names.borrow();
            let by_index = |device: usize| named == format!("if{}", INDEXES[device]);
            let device = if named == names.0 {
                0
            } else if names.1.as_deref() == Some(named)
                || (names.1.is_some() && self.altname == Some(named))
            {
                1
            } else if by_index(0) {
                0
            } else if names.1.is_some() && by_index(1) {
                1
            } else {
                return Err(io::Error::other(format!("Cannot find device \"{named}\"")));
            };
            self.devices.borrow_mut()[device].apply(&words);
        }
        Ok(String::new())
    }
}

impl Kernel for Reuse<'_> {
    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        self.inner.write(path, value)
    }

    fn start<'k>(&'k self, program: &str, args: &[&str]) -> io::Result<Box<dyn Started + 'k>> {
        self.inner.start(program, args)
    }

    fn run(&self, program: &str, args: &[&str], input: &str) -> io::Result<String> {
        match (program, args) {
            ("ip", ["-batch", "-"]) => self.batch(input),
            ("ip", ["-o", "link", "show"]) => {
                let listing = self.inner.run(program, args, input)?;
                let names = self.names.borrow();
                let (Some(other), Some(altname)) = (names.1.as_deref(), self.altname) else {
                    return Ok(listing);
                };
                Ok(listing
                    .lines()
                    .map(|line| match line.split_whitespace().nth(1) {
                        Some(name) if name.strip_suffix(':') == Some(other) => {
                            format!("{line}\\    altname {altname}\n")
                        }
                        _ => format!("{line}\n"),
                    })
                    .collect())
            }
            _ => self.inner.run(program, args, input),
        }
    }

    fn solicit(&self, netdev: &str, hop: Ipv4Addr) -> io::Result<()> {
        self.inner.solicit(netdev, hop)
    }

    fn settle(&self, interval: Duration) {
        self.inner.settle(interval);
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }

    fn open_group(&self, path: &Path) -> io::Result<File> {
        self.inner.open_group(path)
    }

    fn group_status(&self, group: &File) -> io::Result<u32> {
        self.inner.group_status(group)
    }
}

const FOREIGN: &str = "release set network state on a device its record does not name";
const UNRESTORED: &str = "release succeeded without the recorded network state on the device";
const RECORD: &str = "release kept the record of a restored device or dropped an unrestored one's";

/// Judges a release beside another owner's returning device: it may write
/// only the recorded ENI, and it succeeds only with the recorded state on
/// the ENI and its record removed.
fn judge_reuse(
    recorded: &Device,
    result: &Result<(), String>,
    devices: &[Device; 2],
    record_kept: bool,
) -> Result<(), &'static str> {
    if devices[1] != Device::default() {
        return Err(FOREIGN);
    }
    if result.is_ok() && devices[0] != *recorded {
        return Err(UNRESTORED);
    }
    if record_kept != result.is_err() {
        return Err(RECORD);
    }
    Ok(())
}

/// Binds the fixture's ENI, returns it as `eth0` and releases it while the
/// other device takes that name before the batch command at `at`.
fn release_beside(at: Option<usize>) -> (Device, Result<(), String>, [Device; 2], bool) {
    release_beside_as(at, None, None)
}

/// As [`release_beside`], with the other device present under `other`
/// before release starts when it is given, holding `altname` when that is
/// given.
fn release_beside_as(
    at: Option<usize>,
    other: Option<&'static str>,
    altname: Option<&'static str>,
) -> (Device, Result<(), String>, [Device; 2], bool) {
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let bound = bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let recorded = Device::recorded(&bound.eni.as_ref().expect("the ENI's binding").net);
    let net = fixture.host.sys.join("class/net");
    fs::rename(net.join("ens6"), net.join("eth0")).unwrap();
    if let Some(other) = other {
        fixture.netdev(other, OTHER_BDF, OTHER_MAC, 0x1003);
    }
    let Binder {
        host,
        kernel,
        state_dir,
    } = binder;
    let binder = Binder {
        host,
        kernel: Reuse {
            inner: kernel,
            fixture: &fixture,
            at,
            names: RefCell::new(("eth0".to_owned(), other.map(str::to_owned))),
            altname,
            devices: RefCell::default(),
        },
        state_dir,
    };
    let result = binder.release(&[]).map_err(|error| format!("{error:?}"));
    let devices = binder.kernel.devices.take();
    let record_kept = mappings_path(&fixture.state_dir()).exists();
    (recorded, result, devices, record_kept)
}

/// Each owner's release restores only what its own directory records
/// (`bind/mod.rs`, the owner invariant), and the recorded lines are replayed
/// on the ENI. Two owners release at once: udev
/// renames this owner's returned ENI away from its enumerated name, and the
/// other owner's device, returning to `ena`, is enumerated under that name
/// before one of the batch's commands. Whichever command that is, release
/// writes nothing on the other device, and it succeeds only with the whole
/// recorded state on its own ENI.
#[test]
fn release_beside_a_device_that_takes_the_vacated_name_writes_only_its_eni() {
    for at in 0..4 {
        let (recorded, result, devices, record_kept) = release_beside(Some(at));
        assert_eq!(
            judge_reuse(&recorded, &result, &devices, record_kept),
            Ok(()),
            "reuse before command {at}: {result:?}\nENI {:?}\nother {:?}",
            devices[0],
            devices[1]
        );
    }
}

/// `ip` resolves a device word by name, an altname included, before it
/// reads `if<N>` as an interface index, so a device named `if6` takes every
/// command that names the ENI as `if6` (Linux 6.12, iproute2 6.10). Release
/// restores only what its own directory records (`bind/mod.rs`, the owner
/// invariant): beside another device that holds the ENI's index word as its
/// name when release starts, release writes nothing on that device, and it
/// succeeds only with the whole recorded state on its own ENI.
#[test]
fn release_beside_a_device_named_by_the_enis_index_writes_only_its_eni() {
    let word = "if6";
    assert_eq!(word, format!("if{}", INDEXES[0]));
    let (recorded, result, devices, record_kept) = release_beside_as(None, Some(word), None);
    assert_eq!(
        judge_reuse(&recorded, &result, &devices, record_kept),
        Ok(()),
        "{word} present: {result:?}\nENI {:?}\nother {:?}",
        devices[0],
        devices[1]
    );
}

/// As [`release_beside_a_device_named_by_the_enis_index_writes_only_its_eni`],
/// with the other device named `eth1` and holding `if6` as an altname, which
/// `ip` resolves before the index as well.
#[test]
fn release_beside_a_device_altnamed_by_the_enis_index_writes_only_its_eni() {
    let word = "if6";
    assert_eq!(word, format!("if{}", INDEXES[0]));
    let (recorded, result, devices, record_kept) =
        release_beside_as(None, Some("eth1"), Some(word));
    assert_eq!(
        judge_reuse(&recorded, &result, &devices, record_kept),
        Ok(()),
        "{word} held as an altname: {result:?}\nENI {:?}\nother {:?}",
        devices[0],
        devices[1]
    );
}

/// A restore under a name lands on the recorded ENI or runs no command
/// (`Binder::restore_net_as`), whichever device held the name while the
/// index was read. Here udev has renamed the returned ENI to `enp0s1` and
/// the other owner's device holds the ENI's enumerated name, `eth0`. While
/// the restore reads the index under `eth0`, a FIFO here, the other device
/// is renamed to `eth1` and the ENI back to `eth0`, so the name leads to
/// the recorded function once the index, the other device's, is read. The
/// restore refuses and names the other device's index in no command.
#[test]
fn a_restore_under_a_name_another_device_held_for_the_index_read_runs_no_command() {
    use std::io::Write;
    let fixture = Fixture::new(4096);
    let binder = new_binder(&fixture);
    let bound = bind_eni(&binder, None, &FakeMetadata::new()).unwrap();
    let binding = bound.eni.as_ref().expect("the ENI's binding");
    let net = fixture.host.sys.join("class/net");
    fs::rename(net.join("ens6"), net.join("enp0s1")).unwrap();
    fixture.netdev("eth0", OTHER_BDF, OTHER_MAC, 0x1003);
    let index = net.join("eth0/ifindex");
    make_fifo(&index);
    let renamer = {
        let (net, index) = (net.clone(), index.clone());
        std::thread::spawn(move || {
            // Opens once the restore reads the index under `eth0`.
            let mut sink = fs::OpenOptions::new().write(true).open(&index).unwrap();
            fs::rename(net.join("eth0"), net.join("eth1")).unwrap();
            fs::rename(net.join("enp0s1"), net.join("eth0")).unwrap();
            // Later reads of the other device's index find a file again.
            fs::remove_file(net.join("eth1/ifindex")).unwrap();
            fs::write(net.join("eth1/ifindex"), "7\n").unwrap();
            let _sent = sink.write_all(b"7\n");
        })
    };
    let before = binder.kernel.runs.borrow().len();
    let restored = binder.restore_net_as(binding, "eth0");
    let _reader = release(&index);
    renamer.join().unwrap();
    assert_eq!(
        fixture.host.netdev_function("eth0").as_deref(),
        Some(binding.eni.bdf.as_str()),
        "premise: the renames ran, and the name leads to the recorded function"
    );
    let runs = binder.kernel.runs.borrow()[before..].to_vec();
    assert!(
        !runs.iter().any(|run| run.contains(" dev if7")),
        "a restore named the other device's index: {runs:?}"
    );
    assert!(
        matches!(
            restored,
            Err(BindError::Step {
                step: "network",
                ..
            })
        ),
        "{restored:?}"
    );
}
