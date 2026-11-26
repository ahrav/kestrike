//! The table maps each fault kind a cluster profile's fault phase turns on
//! to the production event that produces it and the source of that claim.
//! For fault kinds no generated profile draws, the table gives the
//! recorded reason for exclusion or [`OPEN`].
//!
//! [`drawn_kinds`] names each kind whose rate is above zero in one of the
//! shapes it is given, with the fault table row its draw attaches; the
//! guard gives it every shape a run takes: each profile of [`PROFILES`]
//! that runs as itself and every member of the swarm family. The swarm's
//! envelope and its controls' envelopes list the family, and a swarm
//! control runs a member of the family listed by its envelope.
//! [`drawn_kinds`] destructures [`Shape`], [`Faults`] and [`DeviceFaults`]
//! field by field, selects device kinds through the draw's own
//! [`device_kind`] over every value below the draw's own bound [`DRAW`],
//! and names the fault the draw's own [`device_fault`] builds for each
//! and the fault its [`refused_tear`] puts in place of a refused tear. The
//! matches over the draw's kinds and over the device's [`Fault`] variants
//! have no wildcard arm, so a field, a kind or a fault added to the draw
//! fails to compile until it is named, and a draw that builds another
//! fault draws that fault's kind.
//!
//! The guard [`every_drawn_kind_has_a_production_cause`] fails when a drawn
//! kind has no row marked drawn, a row marked drawn names a kind no shape
//! draws, two rows name one kind, a row leaves its cause, reason or source
//! empty, or a drawn row names another [`Device`] than the one its draw
//! attaches. The link guard of `storage::device::fidelity_tests` reads
//! each row's [`Device`] against the device module's fault table and its
//! tags.
//!
//! The guards read each cause, reason and source for blank text alone.
//! Review checks each text against the source it cites, that a row gives
//! [`OPEN`] where the repository records no reason, and which fault table
//! row an undrawn row names.
//!
//! A source is a text of this repository, an issue of this repository, or
//! public documentation named by its title.

use std::collections::{BTreeMap, BTreeSet};

use crate::storage::Operation;
use crate::storage::owner_fixture::Fault;

use super::{
    DRAW, DeviceFaults, DeviceKind, Faults, PROFILES, Shape, device_fault, device_kind,
    refused_tear, swarm,
};

/// A fault kind, the fault table row it names, and its cause or its
/// reason.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cause {
    /// For a drawn kind, a name [`drawn_kinds`] returns.
    pub(crate) kind: &'static str,
    pub(crate) device: Device,
    pub(crate) account: Account,
}

/// The row of the `storage::device::sim` fault table, or the kind of its
/// exclusion sentence, that a cause row accounts for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Device {
    /// A link kind; the transmit return is the link's too.
    Link,
    /// The fault table row whose Kind cell reads this text.
    Table(&'static str),
    /// A kind the exclusion sentence lists, as it writes it.
    Excluded(&'static str),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Account {
    /// Production produces the drawn kind by `cause`, as `source` records.
    Drawn {
        cause: &'static str,
        source: &'static str,
    },
    /// The kind stays undrawn for `reason`; `source` names where the
    /// reason is recorded, or for [`OPEN`] where the kind is listed.
    NotDrawn {
        reason: &'static str,
        source: &'static str,
    },
}

/// The reason a row gives when the repository records none.
const OPEN: &str = "no reason recorded; open for the owner";

/// The reason of a kind the fault table tags lying.
pub(crate) const LYING: &str = "a lying kind: the device reports success over bytes other than the command's, changes media with no command, posts a completion it did not produce, or answers a stop `Stopped` while it can still execute commands or deliver completions, and the cluster checker holds no damage record that would account for the loss";

const LYING_SOURCE: &str = "#216, gap G3 of its Problem section and its out-of-scope entry on lying read corruption, which waits for a damage record that reaches the cluster checker; `net::world_tests::cluster::tests::every_drawn_device_fault_is_honest`";

const FAULT_TABLE: &str = "the fault table of the `storage::device::sim` module documentation";

/// The fault table row of a status fault that moves no byte.
const ERROR_STATUS: &str = "Error status, no bytes";

/// The fault table row of the corrupt success and the misdirections.
const CORRUPT: &str = "Corrupt success; misdirected read or write";

/// The fault table row of the faults that report nothing.
const UNREPORTED: &str = "Lost command, lost completion, omission, unqualified landing";

/// The kinds a device draw of `kind` can attach to a command of `op`, each
/// with the fault table row it names: the fault [`device_fault`] builds
/// for the draw and, for a prefix draw on a write, the fault
/// [`refused_tear`] gives `fault_command` to attach in place of a tear the
/// device refuses.
fn attached(op: Operation, kind: DeviceKind) -> Vec<(&'static str, &'static str)> {
    let refused = match (op, kind) {
        (Operation::Write, DeviceKind::Prefix) => Some(refused_tear(op)),
        (Operation::Read, DeviceKind::Prefix)
        | (Operation::Read | Operation::Write, DeviceKind::Error) => None,
    };
    [Some(device_fault(op, kind, 1)), refused]
        .into_iter()
        .flatten()
        .map(|fault| named(op, fault))
        .collect()
}

/// The cause-table kind of `fault` on a command of `op`, with the fault
/// table row it names. A status fault takes the name of its operation's
/// error; `every_drawn_device_fault_is_honest` reads how the drawn status
/// classifies.
fn named(op: Operation, fault: Fault) -> (&'static str, &'static str) {
    match fault {
        Fault::Status(_) => match op {
            Operation::Write => ("write error", ERROR_STATUS),
            Operation::Read => ("read error", ERROR_STATUS),
        },
        Fault::Short { .. } => ("short count", "Short count"),
        Fault::CorruptSuccess => ("corrupt success", CORRUPT),
        Fault::TornWrite { .. } => ("torn write", "Torn write"),
        Fault::PartialReadFailure { .. } => ("partial read", "Partial read failure"),
        Fault::MisdirectedRead { .. } | Fault::MisdirectedWrite { .. } => {
            ("misdirected read or write", CORRUPT)
        }
        Fault::DropCommand
        | Fault::DropCompletion
        | Fault::Omit(_)
        | Fault::UnqualifiedLanding { .. } => (
            "lost command, lost completion, omission, unqualified landing",
            UNREPORTED,
        ),
    }
}

const fn drawn_row(
    kind: &'static str,
    device: Device,
    cause: &'static str,
    source: &'static str,
) -> Cause {
    Cause {
        kind,
        device,
        account: Account::Drawn { cause, source },
    }
}

const fn undrawn(
    kind: &'static str,
    device: Device,
    reason: &'static str,
    source: &'static str,
) -> Cause {
    Cause {
        kind,
        device,
        account: Account::NotDrawn { reason, source },
    }
}

/// The committed table: the drawn kinds, then the kinds no generated
/// profile draws.
pub(crate) const CAUSES: [Cause; 33] = [
    drawn_row(
        "loss",
        Device::Link,
        "a datagram dropped on the VPC path, or dropped at an ENI past one of its allowances, which the ENA port counts in its allowance-exceeded counters",
        "`native::ena::ALLOWANCES`; AWS, Monitor network performance for ENA settings on your EC2 instance (packets queued or dropped past an allowance); RFC 8085, UDP Usage Guidelines, section 3.3 (UDP retransmits no lost packet)",
    ),
    drawn_row(
        "duplication",
        Device::Link,
        "the network delivers a second copy of one datagram",
        "RFC 8085, UDP Usage Guidelines, section 3.3 (UDP does not protect against datagram duplication)",
    ),
    drawn_row(
        "reordering",
        Device::Link,
        "datagrams arrive in another order than they left: a peer's requests whose wire slots differ modulo the host's source-port count leave from different source ports, whose flows take separate paths and queues",
        "the `native::burst` module documentation (source ports and flows); RFC 8085, UDP Usage Guidelines, section 3.3",
    ),
    drawn_row(
        "delay",
        Device::Link,
        "a datagram waits in a path or device queue and arrives after later sends",
        "RFC 8085, UDP Usage Guidelines, section 3.3 (the network can significantly delay some packets with respect to others)",
    ),
    drawn_row(
        "stale replay",
        Device::Link,
        "an earlier datagram arrives again after later ones: a duplicate that arrives much later than the first, or an on-path replay. Each session's per-direction replay window drops a copy whose sequence it has seen or that falls at or below the window's floor, and admits a copy whose sequence is unseen and inside the window",
        "RFC 8085, UDP Usage Guidelines, section 3.3; the `net` module documentation (sessions drop replays per direction; the security gate's threat envelope); the `net::session` module documentation (stale and duplicate sequences)",
    ),
    drawn_row(
        "truncation",
        Device::Link,
        "a datagram longer than the receive buffer it reaches: the datagram seam hands back its first `capacity` bytes flagged truncated, and the endpoint drops it. The ENA transport refuses such a frame and counts it dropped: as `Refused::Segments` in its descriptor check when it spans buffers, as `Refused::Length` in that check when its length exceeds the pool's data room, or as `Refused::Length` in its byte check when its length fields disagree with the frame, so a production endpoint meets the event as a lost datagram. Whether a drawn kind that only the seam's contract produces meets R14 of #297 is open for the owner",
        "the `net::datagram` module documentation and `Received::truncated`; `native::wire::Refused`; the receive of `native::burst` (its descriptor and frame checks)",
    ),
    drawn_row(
        "would-block call",
        Device::Link,
        "a send meets a full transmit ring or empty pools and takes an empty prefix the caller resends, or a receive finds no frame the device finished writing and returns an empty batch",
        "the `native::burst` module documentation (pressure stops the accepted prefix); the `net::datagram` module documentation (no datagram ready is a successful empty batch)",
    ),
    drawn_row(
        "failing call",
        Device::Link,
        "the ENA transport refuses a send with `EIO` while a chain it may have kept after a failed native post is quarantined, and a send or a receive with `ESTALE` while the shared registration is unverified",
        "the `native::burst` module documentation",
    ),
    drawn_row(
        "delayed transmit return",
        Device::Link,
        "the ENA port returns a transmit's device references on a later cleanup, after the device read the bytes, and may return one chain's segments in separate cleanups",
        "the `native::burst` module documentation (cleanup); the `net` module documentation, section Transport (each turn's reclaim returns finished transmits)",
    ),
    drawn_row(
        "write error",
        Device::Table(ERROR_STATUS),
        "the EBS volume completes a write with an NVMe error status, which `DeviceStatus::classify` reads as failed; on a range the persistence profile qualifies, the range then holds all old bytes or all new ones. The draw attaches it directly, and in place of a torn write the device refuses on a qualified range",
        "the `storage::device::status` module documentation; the `storage::device::profile` module documentation (landing rule); #216, fault table row `Error status, no bytes`; NVM Express Base Specification, Status Code - Media and Data Integrity Error Values",
    ),
    drawn_row(
        "read error",
        Device::Table(ERROR_STATUS),
        "the EBS volume completes a read with an NVMe error status, such as an unrecovered read error, which `DeviceStatus::classify` reads as failed; a failure status leaves open which bytes moved, so a read that moved none is one of its outcomes",
        "the `storage::device::status` module documentation; the `storage::device::sim` module documentation (a failure status leaves open which bytes moved); #216, fault table row `Error status, no bytes`; NVM Express Base Specification, Status Code - Media and Data Integrity Error Values",
    ),
    drawn_row(
        "torn write",
        Device::Table("Torn write"),
        "a write on a range the persistence profile does not qualify ends with an error status after part of its range reached media; the landing rule says it may leave arbitrary bytes there until a successful completion. The landing rule applies per child command and per the attached volume's profile: an EBS volume's atomic unit is 16,384 bytes, so on EBS a tear can fall on a write the profile leaves unqualified, such as an unaligned write or one longer than the unit. The cluster's devices carry the shared fixture's 4096-byte atomic unit, so the swarm also tears ranges an EBS profile can qualify, such as an aligned 8 KiB write, where an EBS volume leaves all old or all new bytes",
        "the `storage::device::profile` module documentation (landing rule); the `atomic-unit` row of `storage::device::fidelity_tests`; `storage::volume_fixture::facts_for`; #216, fault table row `Torn write`",
    ),
    drawn_row(
        "partial read",
        Device::Table("Partial read failure"),
        "a read ends with an error status after the device wrote part of its buffer: a completion reaches the caller once the device's access to the memory ended, and a failure status leaves open which bytes moved",
        "the `storage::device::disk` module documentation; the `storage::device::sim` module documentation; #216, fault table row `Partial read failure`",
    ),
    undrawn(
        "loss burst",
        Device::Link,
        "the cluster configuration record carries no burst bound, so no cluster shape sets one; the record asserts it is zero",
        "`net::world_tests::cluster`, the configuration record of a run (`config`)",
    ),
    undrawn(
        "resend loss",
        Device::Link,
        "the cluster configuration record carries no resend loss, so no cluster shape sets one; the record asserts it is zero",
        "`net::world_tests::cluster`, the configuration record of a run (`config`)",
    ),
    undrawn(
        "status that classifies as success",
        Device::Table(ERROR_STATUS),
        LYING,
        LYING_SOURCE,
    ),
    undrawn(
        "short count",
        Device::Table("Short count"),
        "the production driver reports NVMe status, which has no short count",
        "#216, plan question OQ4; the `short-transfer` row of `storage::device::fidelity_tests`",
    ),
    undrawn(
        "corrupt success",
        Device::Table(CORRUPT),
        LYING,
        LYING_SOURCE,
    ),
    undrawn(
        "misdirected read or write",
        Device::Table(CORRUPT),
        LYING,
        LYING_SOURCE,
    ),
    undrawn(
        "lost command, lost completion, omission, unqualified landing",
        Device::Table(UNREPORTED),
        OPEN,
        FAULT_TABLE,
    ),
    undrawn(
        "sector damage at rest",
        Device::Table("Sector damage at rest"),
        LYING,
        LYING_SOURCE,
    ),
    undrawn("gray delay", Device::Table("Gray delay"), OPEN, FAULT_TABLE),
    undrawn(
        "submit refusal",
        Device::Table("Submit refusal"),
        "how the owner classes an injected invalid-range refusal was not traced",
        "#216, out of scope: a drawn submit refusal in the swarm",
    ),
    undrawn(
        "misaligned command",
        Device::Table("Misaligned command"),
        "a length that is no multiple of the block breaks the caller's `Disk` precondition, and the simulated device keeps its panic on it",
        "#216, plan question OQ3; the `partial-sector-length` row of `storage::device::fidelity_tests`",
    ),
    undrawn(
        "dead device",
        Device::Table("Dead device"),
        "#29 owns a dead device's composed custody claims, and the cluster world reports node lifecycle as an unavailable dimension",
        "#216, out of scope: a dead device in a generated world; the `net::world_tests::cluster` module documentation",
    ),
    undrawn(
        "sticky read-only",
        Device::Table("Sticky read-only"),
        "a 100% write error rate with sustained phases reaches the same production path",
        "#216, plan question OQ2",
    ),
    undrawn(
        "driver unwind",
        Device::Table("Driver unwind"),
        OPEN,
        FAULT_TABLE,
    ),
    undrawn(
        "stop answer",
        Device::Table("Stop answers"),
        OPEN,
        FAULT_TABLE,
    ),
    undrawn(
        "false stop answer",
        Device::Table("Stop answers"),
        LYING,
        LYING_SOURCE,
    ),
    undrawn(
        "unproduced completion or replayed write",
        Device::Table("Unproduced completion; replayed write"),
        LYING,
        LYING_SOURCE,
    ),
    undrawn(
        "volatile-cache loss",
        Device::Excluded("Volatile-cache loss"),
        "outside the simulated device's fault contract; #60 lists it as a gap of the simulated device",
        "the `storage::device::sim` module documentation; #216, relation to open issues (#60)",
    ),
    undrawn(
        "timeout callbacks",
        Device::Excluded("timeout callbacks"),
        "outside the simulated device's fault contract, which holds media faults: a timeout callback is a driver event",
        "the `fault-kinds` row of `storage::device::fidelity_tests`; the `storage::device::sim` module documentation",
    ),
    undrawn(
        "queue-pair failures",
        Device::Excluded("queue-pair failures"),
        "outside the simulated device's fault contract; #60 asks fault profiles to document it as a gap of the simulated device",
        "the `storage::device::sim` module documentation; #221, relation to open issues (#60) and its fault-kinds row",
    ),
];

/// Maps each fault kind enabled by any shape during its fault phases to the
/// [`Device`] its draw attaches, keyed by cause-table row name.
fn drawn_kinds(shapes: &[Shape]) -> BTreeMap<&'static str, Device> {
    let mut kinds = BTreeMap::new();
    for shape in shapes {
        let Shape {
            faults,
            device,
            delayed_returns,
            name: _,
            owners: _,
            keys: _,
            sizes: _,
            hot: _,
            concurrency: _,
            phases: _,
            phase_ops: _,
            sustained: _,
            invalidate: _,
            versioned: _,
            cancel: _,
            plant: _,
            plant_after: _,
            minima: _,
            gap_us: _,
            window: _,
            first_version: _,
            compact: _,
            uploads: _,
        } = *shape;
        let Faults {
            loss,
            duplicate,
            reorder,
            delay,
            stale,
            truncate,
            would_block,
            error,
            burst,
            resend_loss,
        } = faults;
        let DeviceFaults {
            write_error,
            read_error,
            write_torn,
            read_partial,
        } = device;
        let link = [
            ("loss", loss),
            ("duplication", duplicate),
            ("reordering", reorder),
            ("delay", delay),
            ("stale replay", stale),
            ("truncation", truncate),
            ("would-block call", would_block),
            ("failing call", error),
            ("loss burst", u64::from(burst)),
            ("resend loss", resend_loss),
            ("delayed transmit return", u64::from(delayed_returns)),
        ];
        kinds.extend(
            link.into_iter()
                .filter(|(_, rate)| *rate > 0)
                .map(|(kind, _)| (kind, Device::Link)),
        );
        let device = [
            (Operation::Write, write_error, write_torn),
            (Operation::Read, read_error, read_partial),
        ];
        for (op, error, prefix) in device {
            for value in 0..DRAW {
                if let Some(kind) = device_kind(value, error, prefix) {
                    kinds.extend(
                        attached(op, kind)
                            .into_iter()
                            .map(|(name, cell)| (name, Device::Table(cell))),
                    );
                }
            }
        }
    }
    kinds
}

/// `check` reports the first violation and names the affected kind. Row
/// kinds must be unique, and every row needs a nonblank cause or reason
/// and a nonblank source. The rows marked drawn must name exactly the keys
/// of `kinds`, each with the [`Device`] `kinds` maps it to.
fn check(table: &[Cause], kinds: &BTreeMap<&str, Device>) -> Result<(), String> {
    let mut named = BTreeSet::new();
    for row in table {
        if !named.insert(row.kind) {
            return Err(format!("{} is listed twice", row.kind));
        }
        let (what, text, source) = match row.account {
            Account::Drawn { cause, source } => ("cause", cause, source),
            Account::NotDrawn { reason, source } => ("reason", reason, source),
        };
        if text.trim().is_empty() {
            return Err(format!("{} gives no {what}", row.kind));
        }
        if source.trim().is_empty() {
            return Err(format!("{} gives no source", row.kind));
        }
    }
    let marked: BTreeMap<&str, Device> = table
        .iter()
        .filter(|row| matches!(row.account, Account::Drawn { .. }))
        .map(|row| (row.kind, row.device))
        .collect();
    if let Some(kind) = kinds.keys().find(|kind| !marked.contains_key(*kind)) {
        return Err(format!("{kind} is drawn and has no row marked drawn"));
    }
    for (kind, device) in &marked {
        let Some(attached) = kinds.get(kind) else {
            return Err(format!("{kind} is marked drawn and no shape draws it"));
        };
        if device != attached {
            return Err(format!(
                "{kind} names {device:?} and its draw attaches {attached:?}"
            ));
        }
    }
    Ok(())
}

/// Every shape a run takes: each profile of [`PROFILES`] that runs as
/// itself and every member of the swarm family.
fn committed() -> Vec<Shape> {
    runnable(PROFILES, (0..swarm::MEMBERS).map(swarm::drawn))
}

/// The shapes of `profiles` that run as themselves, then `members`. The
/// swarm's envelope and its controls' envelopes list the family, and a run
/// of one of those profiles takes a member.
fn runnable(
    profiles: impl IntoIterator<Item = Shape>,
    members: impl IntoIterator<Item = Shape>,
) -> Vec<Shape> {
    profiles
        .into_iter()
        .filter(|shape| !listing(shape.name))
        .chain(members)
        .collect()
}

/// Whether the profile `name` is the swarm's envelope or a swarm control's.
fn listing(name: &str) -> bool {
    name == swarm::NAME
        || swarm::CONTROLS
            .iter()
            .any(|&(control, _, _)| control == name)
}

/// The committed table gives every kind the committed shapes draw a row
/// marked drawn with its cause and source, and those shapes draw every
/// kind the table marks drawn.
#[test]
fn every_drawn_kind_has_a_production_cause() {
    if let Err(failure) = check(&CAUSES, &drawn_kinds(&committed())) {
        panic!("{failure}");
    }
}

/// The six lying kinds each keep a row of their own, marked not drawn for
/// the lying reason and naming its fault table row.
#[test]
fn each_lying_kind_keeps_its_own_row() {
    let corrupt = Device::Table("Corrupt success; misdirected read or write");
    let expected = BTreeSet::from([
        (
            "status that classifies as success",
            Device::Table(ERROR_STATUS),
        ),
        ("corrupt success", corrupt),
        ("misdirected read or write", corrupt),
        (
            "sector damage at rest",
            Device::Table("Sector damage at rest"),
        ),
        ("false stop answer", Device::Table("Stop answers")),
        (
            "unproduced completion or replayed write",
            Device::Table("Unproduced completion; replayed write"),
        ),
    ]);
    let lying: BTreeSet<(&str, Device)> = CAUSES
        .iter()
        .filter(|row| {
            matches!(row.account, Account::NotDrawn { reason, source }
                if reason == LYING && source == LYING_SOURCE)
        })
        .map(|row| (row.kind, row.device))
        .collect();
    assert_eq!(lying, expected);
}

#[test]
fn each_fault_rate_draws_the_kind_its_row_names() {
    let quiet = Shape {
        faults: Faults::default(),
        device: super::SOUND,
        delayed_returns: false,
        ..PROFILES[0]
    };
    let link = |faults: Faults| Shape { faults, ..quiet };
    let device = |device: DeviceFaults| Shape { device, ..quiet };
    let one = Faults::default();
    let sound = super::SOUND;
    let links = [
        (link(Faults { loss: 1, ..one }), "loss"),
        (
            link(Faults {
                duplicate: 1,
                ..one
            }),
            "duplication",
        ),
        (link(Faults { reorder: 1, ..one }), "reordering"),
        (link(Faults { delay: 1, ..one }), "delay"),
        (link(Faults { stale: 1, ..one }), "stale replay"),
        (link(Faults { truncate: 1, ..one }), "truncation"),
        (
            link(Faults {
                would_block: 1,
                ..one
            }),
            "would-block call",
        ),
        (link(Faults { error: 1, ..one }), "failing call"),
        (link(Faults { burst: 1, ..one }), "loss burst"),
        (
            link(Faults {
                resend_loss: 1,
                ..one
            }),
            "resend loss",
        ),
        (
            Shape {
                delayed_returns: true,
                ..quiet
            },
            "delayed transmit return",
        ),
    ];
    let error = ("write error", Device::Table(ERROR_STATUS));
    let devices = [
        (
            device(DeviceFaults {
                write_error: 1,
                ..sound
            }),
            vec![error],
        ),
        (
            device(DeviceFaults {
                read_error: 1,
                ..sound
            }),
            vec![("read error", Device::Table(ERROR_STATUS))],
        ),
        (
            device(DeviceFaults {
                write_torn: 1,
                ..sound
            }),
            vec![("torn write", Device::Table("Torn write")), error],
        ),
        (
            device(DeviceFaults {
                read_partial: 1,
                ..sound
            }),
            vec![("partial read", Device::Table("Partial read failure"))],
        ),
    ];
    // With rates of 99 and 1 the draw's last value alone selects the
    // prefix kind, so the kinds come from every value the draw takes.
    let both = BTreeMap::from([
        error,
        ("torn write", Device::Table("Torn write")),
        ("read error", Device::Table(ERROR_STATUS)),
        ("partial read", Device::Table("Partial read failure")),
    ]);
    let last = device(DeviceFaults {
        write_error: 99,
        read_error: 99,
        write_torn: 1,
        read_partial: 1,
    });
    assert_eq!(drawn_kinds(&[last]), both);
    assert_eq!(drawn_kinds(&[quiet]), BTreeMap::new());
    for (shape, kind) in links {
        let expected = BTreeMap::from([(kind, Device::Link)]);
        assert_eq!(drawn_kinds(&[shape]), expected, "{shape:?}");
    }
    for (shape, kinds) in devices {
        let expected = kinds.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(drawn_kinds(&[shape]), expected, "{shape:?}");
    }
}

fn without(kind: &str) -> Vec<Cause> {
    CAUSES.into_iter().filter(|row| row.kind != kind).collect()
}

fn replaced(row: Cause) -> Vec<Cause> {
    CAUSES
        .into_iter()
        .map(|old| if old.kind == row.kind { row } else { old })
        .collect()
}

#[test]
fn a_drawn_kind_without_a_production_cause_fails_the_guard() {
    let kinds = drawn_kinds(&committed());
    let guard = |table: &[Cause]| check(table, &kinds);
    assert_eq!(
        guard(&without("torn write")),
        Err("torn write is drawn and has no row marked drawn".to_owned())
    );
    assert_eq!(
        guard(&replaced(drawn_row("loss", Device::Link, " ", "RFC 8085"))),
        Err("loss gives no cause".to_owned())
    );
    assert_eq!(
        guard(&replaced(drawn_row(
            "loss",
            Device::Link,
            "a lost datagram",
            ""
        ))),
        Err("loss gives no source".to_owned())
    );
    let gray = Device::Table("Gray delay");
    assert_eq!(
        guard(&replaced(undrawn("gray delay", gray, "", FAULT_TABLE))),
        Err("gray delay gives no reason".to_owned())
    );
    assert_eq!(
        guard(&replaced(undrawn("gray delay", gray, OPEN, " "))),
        Err("gray delay gives no source".to_owned())
    );
    let mut twice = CAUSES.to_vec();
    twice.push(CAUSES[0]);
    assert_eq!(
        guard(&twice),
        Err(format!("{} is listed twice", CAUSES[0].kind))
    );
    assert_eq!(
        guard(&replaced(drawn_row(
            "write error",
            Device::Link,
            "an error status",
            "a source"
        ))),
        Err(
            "write error names Link and its draw attaches Table(\"Error status, no bytes\")"
                .to_owned()
        )
    );
    let torn = Device::Table("Torn write");
    let partial = Device::Table("Partial read failure");
    let swapped: Vec<Cause> = CAUSES
        .into_iter()
        .map(|row| match row.device {
            device if device == torn => Cause {
                device: partial,
                ..row
            },
            device if device == partial => Cause {
                device: torn,
                ..row
            },
            _ => row,
        })
        .collect();
    assert_eq!(
        guard(&swapped),
        Err(
            "partial read names Table(\"Torn write\") and its draw attaches Table(\"Partial read failure\")"
                .to_owned()
        )
    );
    assert_eq!(
        guard(&replaced(drawn_row(
            "delay",
            gray,
            "a queued datagram",
            "RFC 8085"
        ))),
        Err("delay names Table(\"Gray delay\") and its draw attaches Link".to_owned())
    );
    // A draw that builds a short count draws a kind the table marks not
    // drawn.
    let (short, cell) = named(Operation::Read, Fault::Short { units: 1 });
    let mut shortened = kinds.clone();
    shortened.insert(short, Device::Table(cell));
    assert_eq!(
        check(&CAUSES, &shortened),
        Err("short count is drawn and has no row marked drawn".to_owned())
    );
    let mut bursty = committed();
    bursty.push(Shape {
        faults: Faults {
            burst: 1,
            ..PROFILES[0].faults
        },
        ..PROFILES[0]
    });
    assert_eq!(
        check(&CAUSES, &drawn_kinds(&bursty)),
        Err("loss burst is drawn and has no row marked drawn".to_owned())
    );
    // The swarm's envelope and each control's are the listing entries, and
    // the guard reads every other profile and every member.
    let listed = PROFILES.iter().filter(|shape| listing(shape.name)).count();
    assert_eq!(listed, 1 + swarm::CONTROLS.len());
    assert_eq!(
        committed().len() as u64,
        (PROFILES.len() - listed) as u64 + swarm::MEMBERS
    );
    let untorn = |shape: Shape| Shape {
        device: DeviceFaults {
            write_torn: 0,
            ..shape.device
        },
        ..shape
    };
    let profiles = PROFILES.map(|shape| {
        if listing(shape.name) {
            shape
        } else {
            untorn(shape)
        }
    });
    assert!(profiles.iter().any(|shape| shape.device.write_torn > 0));
    let members = (0..swarm::MEMBERS).map(|index| untorn(swarm::drawn(index)));
    assert_eq!(
        check(&CAUSES, &drawn_kinds(&runnable(profiles, members))),
        Err("torn write is marked drawn and no shape draws it".to_owned())
    );
}
