//! The table lists differences between the simulated device and the
//! production driver, with a pin for each side of each row, and the guard
//! fails when a row loses a pin.
//!
//! For each row, the simulated device behaves as its `simulated` text
//! states and the production driver as its `production` text states, and
//! each side's pin asserts that side's behavior. A row also gives the
//! reason for the difference and how the disk contract's legs treat it,
//! where a leg is one run of the disk contract on one device. A `Within`
//! treatment names how the contract or its leg runs over the difference.
//! An `Outside` treatment names the condition that places the difference
//! outside every leg. A pass on the simulated device, a campaign's or a
//! leg's, shows nothing about a row's production side.
//!
//! A test pin is a test of this crate that the ordinary selection requires:
//! a `workspace` record of `verification/obligations.json` cites it, or
//! `scripts/test-inventory.json` names it as an anchor. A production side
//! may instead carry a hardware pin: a case ID under a profile of
//! `scripts/hardware-profiles.json` whose disposition on every aarch64 row
//! is `runs` or `pending`, since aarch64 is the production architecture.
//! Credit for a hardware pin requires a credited run on an aarch64 row.
//!
//! The guard checks that each test pin is a required test and each
//! hardware pin an aarch64 case; review checks that each pinned test
//! asserts its row. The guard sees listed rows only.
//!
//! The production device progresses independently, and the simulated
//! device progresses when its control half ticks it. The disk contract's
//! caller accommodates both progress models through its `progress` closure
//! and observation interval. The table lists the differences that remain
//! after the caller accommodates both progress models.
//!
//! The link guard reads the fault table and the exclusion sentence of the
//! `storage::device::sim` module documentation. For each fault-table kind,
//! `net::world_tests::cluster::causes::CAUSES` must contain a
//! `Device::Table(kind)` row or [`DOCUMENTED`] must contain a `(kind, id)`
//! entry. For each kind of the exclusion sentence, `CAUSES` must contain a
//! `Device::Excluded(kind)` row whose account is `Account::NotDrawn`. Every
//! kind those rows name must stand in that documentation. The guard reads
//! each fault table row's Tag cell too: a row of `CAUSES` marked drawn
//! names a kind whose tag begins `Honest`, a row that gives the lying
//! reason is a `Device::Table(kind)` row whose kind's tag mentions lying,
//! and each kind whose tag mentions lying has a row that gives the lying
//! reason.

use std::collections::BTreeSet;

use crate::net::terminal_tests::{INVENTORY, OBLIGATIONS, anchors, record_tests, workspace_tests};
use crate::net::world_tests::cluster::causes::{Account, CAUSES, Cause, Device, LYING};

const MANIFEST: &str = include_str!("../../../../../scripts/hardware-profiles.json");

const GUARD: &str = "storage::device::fidelity_tests::every_listed_difference_is_pinned";

const RECORD: &str = "simulated-device-differences-are-pinned-on-both-sides";

#[expect(
    dead_code,
    reason = "a reader reads the sides and the treatment; the guard reads the id, the reason and the pins"
)]
#[derive(Clone, Copy)]
struct Difference {
    id: &'static str,
    simulated: &'static str,
    production: &'static str,
    reason: &'static str,
    treatment: Treatment,
    /// The test that asserts the simulated side.
    simulated_pin: &'static str,
    production_pin: Pin,
}

/// How the disk contract's legs treat a difference.
#[expect(dead_code, reason = "a reader reads the treatment's text")]
#[derive(Clone, Copy)]
enum Treatment {
    /// The text names how the contract or its leg runs over the difference.
    Within(&'static str),
    /// The text names the condition that places the difference outside every leg.
    Outside(&'static str),
}

#[derive(Clone, Copy)]
enum Pin {
    /// A test by its module path in this crate.
    Test(&'static str),
    /// A hardware case ID of the manifest.
    Hardware(&'static str),
}

const DIFFERENCES: [Difference; 11] = [
    Difference {
        id: "status-form",
        simulated: "the shared fixture's device reports a whole read as `Kernel(len)` and a read that fails part way as `Kernel(-EIO)`",
        production: "the driver delivers the NVMe status word as `Nvme(raw)`, unchanged",
        reason: "a kernel result carries the transferred byte count, which a fixture needs to express a short transfer",
        treatment: Treatment::Within(
            "the contract reads every status through `classify`, and a simulated leg runs each form; every leg runs with faults off, so the legs read success statuses only",
        ),
        simulated_pin: "storage::device::sim_tests::the_shared_fixture_device_reports_kernel_status",
        production_pin: Pin::Test(
            "storage::device::spdk::outstanding_tests::a_rewritten_status_reaches_the_failed_terminal_unchanged",
        ),
    },
    Difference {
        id: "short-transfer",
        simulated: "`Fault::Short` reports the moved byte count as a kernel result in either form, and a count below the command's length classifies `Short`",
        production: "an NVMe status word classifies `Success` or `Failed` by its code and type alone, and never `Short`",
        reason: "the fault contract expresses a short transfer through a kernel count in either form",
        treatment: Treatment::Outside("every leg runs with faults off"),
        simulated_pin: "storage::device::sim_tests::a_short_fault_reports_a_kernel_count_in_either_form",
        production_pin: Pin::Test(
            "storage::device::status::tests::every_nvme_status_word_classifies_by_its_code_and_type_alone",
        ),
    },
    Difference {
        id: "stop-proof",
        simulated: "`quiesce` answers `Pending` under the construction mode, `AllReturned`, while commands keep completing, and `Stopped` at once under `QuiesceMode::Reset`, which drops every outstanding command",
        production: "the driver proves a stop only after register reads show CC.EN = 0 and CSTS.RDY = 0, and keeps every command until then",
        reason: "a reset of the simulated device ends its commands in one call, and the driver reads controller registers to prove its stop",
        treatment: Treatment::Within(
            "each simulated leg selects `Reset`, and the contract calls `quiesce` until it answers `Stopped`",
        ),
        simulated_pin: "storage::device::sim_tests::quiesce_reports_stopped_only_after_a_reset",
        production_pin: Pin::Test(
            "storage::device::spdk::stop_tests::a_failed_poll_holds_every_command_until_a_proven_stop_quiesces_them",
        ),
    },
    Difference {
        id: "reservation-commands",
        simulated: "the device reports no reservation limits and refuses a reservation command `Unsupported`",
        production: "a driver without an attach authority that reports reservation limits completes a Report with NVMe status; from those limits the command table holds a share of its depth for reservation commands beside reads and writes, under a per-tick quota",
        reason: "the simulated device keeps the trait's reservation defaults; the volume gate fixture's wrapper answers reservation commands from a table",
        treatment: Treatment::Outside("the contract submits reads and writes only"),
        simulated_pin: "storage::device::sim_tests::a_simulated_device_has_no_reservation_commands",
        production_pin: Pin::Test(
            "storage::device::spdk::reservation_tests::every_data_and_metadata_slot_busy_leaves_the_separate_report_share_and_tick_quota",
        ),
    },
    Difference {
        id: "registration",
        simulated: "the device accepts a command over any buffer of the caller's arena, with no registration step, and moves its bytes",
        production: "a driver without an attach authority refuses a command `NotVerified` until its registered arena is verified, here by the canary, then refuses memory outside the arena `InvalidRange` and accepts a command inside it",
        reason: "the simulated device in direct mode copies bytes through the range's pointer on the caller's thread, and the driver's device reaches memory through a mapping the canary verifies",
        treatment: Treatment::Within(
            "the hardware leg registers and verifies its arena before the contract runs",
        ),
        simulated_pin: "storage::device::sim_tests::direct_mode_reads_and_writes_the_buffer_through_its_range",
        production_pin: Pin::Test(
            "storage::device::spdk::disk_tests::commands_are_refused_until_the_canary_passes",
        ),
    },
    Difference {
        id: "medium-gate",
        simulated: "the device serves reads and writes with no `admit_medium` call",
        production: "a running driver that holds an attach authority refuses every read and write `NotVerified` until `admit_medium` names its own pair after its reservation gate passed",
        reason: "the simulated device holds no attach authority; the driver's authority withholds the medium until the volume's gate passes",
        treatment: Treatment::Outside(
            "the contract never calls `admit_medium`, and the hardware leg attaches through the qualification path, which installs no attach authority",
        ),
        simulated_pin: "storage::device::sim_tests::direct_mode_reads_and_writes_the_buffer_through_its_range",
        production_pin: Pin::Test(
            "storage::device::spdk::reservation_tests::medium_admission_opens_an_authority_disk_after_the_reservation_gate_alone",
        ),
    },
    Difference {
        id: "partial-sector-length",
        simulated: "a length that is no multiple of the block size panics as a broken `Disk` precondition",
        production: "a driver that serves reads and writes refuses a length that is no multiple of its sector size `InvalidRange` and makes no native call",
        reason: "a whole-block length is the caller's precondition; the simulated device stops a test at the caller's defect",
        treatment: Treatment::Outside("the contract submits whole I/O units only"),
        simulated_pin: "storage::device::sim_tests::a_submit_of_a_partial_block_breaks_the_precondition",
        production_pin: Pin::Test(
            "storage::device::spdk::disk_tests::a_submit_admits_only_whole_sector_lengths_inside_the_limits",
        ),
    },
    Difference {
        id: "atomic-unit",
        simulated: "the shared fixture's attach facts derive a 4096-byte atomic unit of 512-byte sectors by default, and the unit a held `volume_fixture::Unit` guard sets, 16,384 bytes in the wide-unit histories",
        production: "an EBS volume's attach facts derive a 16,384-byte atomic unit",
        reason: "the unit is the volume's own; the fixture's facts set the 4096-byte metadata block as the default unit, and `Geometry::WideUnit` runs hold the EBS unit",
        treatment: Treatment::Outside(
            "the disk contract reads no atomic unit; the persistence contract derives the unit per backend from `attach_facts`",
        ),
        simulated_pin: "storage::device::sim_tests::the_shared_fixture_device_derives_the_default_and_held_atomic_units",
        production_pin: Pin::Hardware(
            "storage::device::spdk::hardware_tests::the_attached_volume_derives_a_persistence_profile",
        ),
    },
    Difference {
        id: "fault-kinds",
        simulated: "an omitted completion is never reported as a timeout: the command stays outstanding, with nothing reported for it, through `Pending` and `Failed` quiesce answers until a reset",
        production: "the driver counts a timeout callback for an outstanding command and keeps every command's custody until its terminal",
        reason: "the simulated device's fault contract holds media faults, and a timeout callback is a driver event outside it",
        treatment: Treatment::Outside("every leg runs with faults off"),
        simulated_pin: "storage::device::fault_tests::an_omission_holds_the_command_until_a_proven_stop",
        production_pin: Pin::Test(
            "storage::device::spdk::outstanding_tests::a_report_only_timeout_retains_every_command_and_bounds_admission",
        ),
    },
    Difference {
        id: "token-reuse",
        simulated: "a submit that reuses the token of a command still pending panics as a broken `Disk` precondition",
        production: "the driver's staging takes a record of its own for a token already outstanding",
        reason: "a unique token is the caller's precondition; the simulated device stops a test at the caller's defect",
        treatment: Treatment::Outside("the contract gives every command its own token"),
        simulated_pin: "storage::device::sim_tests::a_submit_reusing_a_pending_token_breaks_the_precondition",
        production_pin: Pin::Test(
            "storage::device::spdk::staging_tests::a_repeated_token_takes_a_record_of_its_own",
        ),
    },
    Difference {
        id: "controller-events",
        simulated: "a scripted abort status reaches the caller as written, and the device keeps accepting and completing commands",
        production: "an abort or queue-deletion status, or a failed poll, records a controller event and turns the driver gone",
        reason: "the simulated device reports a status without reading it; the driver ends its incarnation at a controller event",
        treatment: Treatment::Outside(
            "every leg runs with faults off, so every status the contract reads is a success",
        ),
        simulated_pin: "storage::device::sim_tests::an_abort_status_reaches_the_caller_and_the_device_keeps_serving",
        production_pin: Pin::Test(
            "storage::device::spdk::disk_tests::a_mid_tenure_controller_event_ends_submission",
        ),
    },
];

struct Sources<'s> {
    cited: BTreeSet<&'s str>,
    anchors: BTreeSet<&'s str>,
    cases: BTreeSet<String>,
    record: BTreeSet<&'s str>,
}

impl Sources<'static> {
    fn committed() -> Self {
        Sources {
            cited: workspace_tests(&OBLIGATIONS),
            anchors: anchors(&INVENTORY),
            cases: aarch64_cases(MANIFEST),
            record: record_tests(&OBLIGATIONS, RECORD),
        }
    }
}

/// The case IDs a profile role of the manifest declares.
fn case_ids(role: &serde_json::Value) -> impl Iterator<Item = &str> {
    role["cases"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|case| case["id"].as_str().expect("a case ID"))
}

/// The case IDs under each profile of `manifest` whose disposition on every
/// aarch64 platform row is `runs` or `pending`.
fn aarch64_cases(manifest: &str) -> BTreeSet<String> {
    let manifest: serde_json::Value = serde_json::from_str(manifest).expect("the manifest parses");
    let rows: Vec<&str> = manifest["platforms"]
        .as_object()
        .expect("the manifest's platforms")
        .iter()
        .filter(|(_, row)| row["machine"] == "aarch64")
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(!rows.is_empty(), "the manifest declares an aarch64 row");
    let mut cases = BTreeSet::new();
    for profile in manifest["profiles"]
        .as_object()
        .expect("the manifest's profiles")
        .values()
    {
        let runs = rows
            .iter()
            .all(|row| matches!(profile["platforms"][row].as_str(), Some("runs" | "pending")));
        if !runs {
            continue;
        }
        for role in profile["roles"]
            .as_object()
            .expect("a profile's roles")
            .values()
        {
            cases.extend(case_ids(role).map(str::to_owned));
        }
    }
    cases
}

/// Runs the guard's checks over `table` in order and returns the first
/// failure's text: the table is non-empty, its ids are unique, each row
/// gives a reason, each test pin is a required test of the ordinary
/// selection, each hardware pin is an aarch64 case, and the record's
/// `tests` contain exactly the guard and the test pins left after the
/// inventory anchors are filtered out. A per-row failure names its row.
fn check(table: &[Difference], sources: &Sources<'_>) -> Result<(), String> {
    if table.is_empty() {
        return Err("the differences table is empty".to_owned());
    }
    let mut ids = BTreeSet::new();
    for row in table {
        if !ids.insert(row.id) {
            return Err(format!("{} is listed twice", row.id));
        }
    }
    if let Some(row) = table.iter().find(|row| row.reason.trim().is_empty()) {
        return Err(format!("{} gives no reason", row.id));
    }
    let mut pins = BTreeSet::new();
    for row in table {
        let production = match row.production_pin {
            Pin::Test(test) => Some(test),
            Pin::Hardware(_) => None,
        };
        for test in std::iter::once(row.simulated_pin).chain(production) {
            if !sources.cited.contains(test) && !sources.anchors.contains(test) {
                return Err(format!("{}: {test} is not a required test", row.id));
            }
            pins.insert(test);
        }
    }
    for row in table {
        if let Pin::Hardware(case) = row.production_pin
            && !sources.cases.contains(case)
        {
            return Err(format!(
                "{}: {case} is no case of a profile every aarch64 row runs or holds pending",
                row.id
            ));
        }
    }
    let expected: BTreeSet<&str> = std::iter::once(GUARD)
        .chain(pins.difference(&sources.anchors).copied())
        .collect();
    if sources.record != expected {
        return Err(format!(
            "the record's tests and the guard with the table's test pins differ: missing {:?}, extra {:?}",
            expected.difference(&sources.record).collect::<Vec<_>>(),
            sources.record.difference(&expected).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

/// The committed table passes `check` against the committed catalog,
/// inventory and manifest.
#[test]
fn every_listed_difference_is_pinned() {
    if let Err(failure) = check(&DIFFERENCES, &Sources::committed()) {
        panic!("{failure}");
    }
}

fn with(row: Difference) -> Vec<Difference> {
    let mut table = DIFFERENCES.to_vec();
    table.push(row);
    table
}

/// Each plant isolates one guard check. The plant for the citation check
/// runs last and passes the checks before it, so the control panics with
/// its failure text, which names the planted row.
#[test]
#[should_panic(expected = "uncited-pin: storage::device::uncited is not a required test")]
fn a_difference_without_a_cited_pin_fails_the_guard() {
    let committed = Sources::committed();
    assert_eq!(
        check(&[], &committed),
        Err("the differences table is empty".to_owned())
    );
    assert_eq!(
        check(&with(DIFFERENCES[0]), &committed),
        Err(format!("{} is listed twice", DIFFERENCES[0].id))
    );
    let silent = Difference {
        id: "no-reason",
        reason: " ",
        ..DIFFERENCES[0]
    };
    assert_eq!(
        check(&with(silent), &committed),
        Err("no-reason gives no reason".to_owned())
    );
    // Row `x` excludes the profile in every input, so the passing twin
    // returns the case only while the filter judges the aarch64 rows alone,
    // and each aarch64 row excludes the profile in one failing input.
    let split = |a: &str, b: &str| {
        r#"{"platforms": {"a": {"machine": "aarch64"}, "b": {"machine": "aarch64"},
        "x": {"machine": "x86_64"}},
        "profiles": {"p": {"platforms": {"a": "A", "b": "B", "x": "excluded"},
        "roles": {"owner": {"cases": [{"id": "p::case"}]}}}}}"#
            .replace("\"A\"", &format!("\"{a}\""))
            .replace("\"B\"", &format!("\"{b}\""))
    };
    assert_eq!(aarch64_cases(&split("runs", "excluded")), BTreeSet::new());
    assert_eq!(
        aarch64_cases(&split("excluded", "pending")),
        BTreeSet::new()
    );
    assert_eq!(
        aarch64_cases(&split("runs", "pending")),
        BTreeSet::from(["p::case".to_owned()])
    );
    let fis = "storage::device::spdk::hardware_tests::a_read_under_an_injected_fault_reports_its_timeout_and_ends_exact_at_its_late_terminal";
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).expect("the manifest parses");
    let declared = manifest["profiles"]["fis-read"]["roles"]
        .as_object()
        .expect("the fis-read profile's roles")
        .values()
        .flat_map(case_ids)
        .any(|case| case == fis);
    assert!(
        declared,
        "the plant {fis} is a case ID of the fis-read profile"
    );
    let excluded = Difference {
        id: "fis-pin",
        production_pin: Pin::Hardware(fis),
        ..DIFFERENCES[0]
    };
    assert_eq!(
        check(&with(excluded), &committed),
        Err(format!(
            "fis-pin: {fis} is no case of a profile every aarch64 row runs or holds pending"
        ))
    );
    let mut dropped = Sources::committed();
    let pin = *dropped
        .record
        .iter()
        .find(|test| **test != GUARD)
        .expect("the record cites a pin");
    assert!(dropped.record.remove(pin));
    assert_eq!(
        check(&DIFFERENCES, &dropped),
        Err(format!(
            "the record's tests and the guard with the table's test pins differ: missing [{pin:?}], extra []"
        ))
    );
    let mut extra = Sources::committed();
    assert!(extra.record.insert("storage::device::extra"));
    assert_eq!(
        check(&DIFFERENCES, &extra),
        Err(
            "the record's tests and the guard with the table's test pins differ: missing [], extra [\"storage::device::extra\"]"
                .to_owned()
        )
    );
    let uncited = Difference {
        id: "uncited-pin",
        simulated_pin: "storage::device::uncited",
        ..DIFFERENCES[0]
    };
    if let Err(failure) = check(&with(uncited), &committed) {
        panic!("{failure}");
    }
}

/// The device module's source, whose documentation holds the fault table.
const SIM: &str = include_str!("sim.rs");

/// Pairs of a kind of the device module documentation and the id of the
/// [`DIFFERENCES`] row that documents it. The guard checks that each id
/// identifies a row.
const DOCUMENTED: [(&str, &str); 4] = [
    ("Short count", "short-transfer"),
    ("Misaligned command", "partial-sector-length"),
    ("Stop answers", "stop-proof"),
    ("timeout callbacks", "fault-kinds"),
];

/// The end of the module documentation's sentence that lists the kinds
/// outside the fault contract.
const OUTSIDE: &str = " lie outside the device's fault contract.";

const HEADER: [&str; 2] = ["| Kind | Symbol | Tag |", "| --- | --- | --- |"];

/// The kinds the device module documentation names.
struct Kinds<'a> {
    /// Each fault table row's Kind cell with its Tag cell.
    table: Vec<(&'a str, &'a str)>,
    /// Each kind the exclusion sentence lists.
    excluded: Vec<String>,
}

/// The kinds the leading module documentation of `source` names: the Kind
/// cell of each fault table row with its Tag cell, and each kind the one
/// sentence ending in [`OUTSIDE`] lists. `fault_kinds` splits the list on
/// `", "` and `" and "`, and the sentence may wrap across documentation
/// lines. A
/// missing header, separator or row, a table line outside the three-cell
/// form, a table line apart from the table, or a second exclusion sentence
/// is an error.
fn fault_kinds(source: &str) -> Result<Kinds<'_>, String> {
    let lines: Vec<&str> = source
        .lines()
        .map_while(|line| line.strip_prefix("//!"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect();
    let Some(head) = lines.iter().position(|&line| line == HEADER[0]) else {
        return Err("the device module documentation holds no fault table".to_owned());
    };
    if lines.get(head + 1) != Some(&HEADER[1]) {
        return Err("the fault table has no separator under its header".to_owned());
    }
    let body = head + 2;
    let end = lines[body..]
        .iter()
        .position(|line| !line.trim_start().starts_with('|'))
        .map_or(lines.len(), |at| body + at);
    let mut table = Vec::new();
    for &line in &lines[body..end] {
        let cells = line
            .strip_prefix("| ")
            .and_then(|row| row.strip_suffix(" |"))
            .map(|row| row.split(" | ").collect::<Vec<_>>());
        match cells.as_deref() {
            Some(&[kind, _, tag]) => table.push((kind, tag)),
            _ => {
                return Err(format!(
                    "the fault table row `{line}` has another form than `| Kind | Symbol | Tag |`"
                ));
            }
        }
    }
    if table.is_empty() {
        return Err("the fault table holds no row".to_owned());
    }
    let apart = lines[..head]
        .iter()
        .chain(&lines[end..])
        .find(|line| line.trim_start().starts_with('|'));
    if let Some(line) = apart {
        return Err(format!(
            "`{line}` is a table line apart from the fault table"
        ));
    }
    let prose = lines.join(" ");
    let mut sentences = prose.match_indices(OUTSIDE);
    let Some((at, _)) = sentences.next() else {
        return Err(
            "the device module documentation excludes no kind from the fault contract".to_owned(),
        );
    };
    if sentences.next().is_some() {
        return Err("the device module documentation holds two exclusion sentences".to_owned());
    }
    let head = &prose[..at];
    let sentence = head.rsplit_once(". ").map_or(head, |(_, last)| last);
    let excluded = sentence
        .split(", ")
        .flat_map(|part| part.split(" and "))
        .map(|kind| kind.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    Ok(Kinds { table, excluded })
}

/// `link` checks `causes` and `documented` against the module
/// documentation in `source` and returns the first failure's text. The
/// documentation must parse. `Device::Table(kind)` requires `kind` in the
/// fault table and `Device::Excluded(kind)` requires it in the exclusion
/// sentence; each kind in `documented` must appear in either, and each id
/// in `documented` must identify a row of [`DIFFERENCES`]. Each kind of the
/// fault table needs a `Device::Table(kind)` row in `causes` or a
/// `(kind, id)` entry in `documented`, and each kind of the exclusion
/// sentence needs a `Device::Excluded(kind)` row in `causes` whose account
/// is [`Account::NotDrawn`]. A row marked drawn must name a kind whose Tag
/// cell begins `Honest`, a row whose reason is [`LYING`] must be a
/// `Device::Table(kind)` row whose kind's tag mentions lying, and each kind
/// whose tag mentions lying needs a row whose reason is [`LYING`].
fn link(causes: &[Cause], documented: &[(&str, &str)], source: &str) -> Result<(), String> {
    let Kinds { table, excluded } = fault_kinds(source)?;
    let tag_of = |kind: &str| {
        let row = table.iter().find(|&&(named, _)| named == kind);
        row.map(|&(_, tag)| tag)
    };
    let in_table = |kind: &str| tag_of(kind).is_some();
    let in_sentence = |kind: &str| excluded.iter().any(|named| named == kind);
    let lying = |tag: &str| tag.to_ascii_lowercase().contains("lying");
    let gives_lying =
        |row: &Cause| matches!(row.account, Account::NotDrawn { reason, .. } if reason == LYING);
    for row in causes {
        let unknown = |kind: &str| {
            format!(
                "{}: {kind} is no kind the device module documentation names",
                row.kind
            )
        };
        let (kind, tag) = match row.device {
            Device::Table(kind) => (kind, tag_of(kind).ok_or_else(|| unknown(kind))?),
            Device::Excluded(kind) if !in_sentence(kind) => return Err(unknown(kind)),
            Device::Link | Device::Excluded(_) if gives_lying(row) => {
                return Err(format!(
                    "{} gives the lying reason and names no fault table kind",
                    row.kind
                ));
            }
            Device::Link | Device::Excluded(_) => continue,
        };
        if matches!(row.account, Account::Drawn { .. }) && !tag.starts_with("Honest") {
            return Err(format!(
                "{} is marked drawn and the fault table tags {kind} `{tag}`",
                row.kind
            ));
        }
        if gives_lying(row) && !lying(tag) {
            return Err(format!(
                "{} gives the lying reason and the fault table tags {kind} `{tag}`",
                row.kind
            ));
        }
    }
    for &(kind, id) in documented {
        if !in_table(kind) && !in_sentence(kind) {
            return Err(format!(
                "{id}: {kind} is no kind the device module documentation names"
            ));
        }
        if !DIFFERENCES.iter().any(|row| row.id == id) {
            return Err(format!("{kind}: {id} is no row of the differences table"));
        }
    }
    for &(kind, tag) in &table {
        let rows = || {
            causes
                .iter()
                .filter(|row| matches!(row.device, Device::Table(named) if named == kind))
        };
        let by_difference = documented.iter().any(|&(named, _)| named == kind);
        if rows().next().is_none() && !by_difference {
            return Err(format!("{kind} is named by no row"));
        }
        if lying(tag) && !rows().any(gives_lying) {
            return Err(format!(
                "the fault table tags {kind} `{tag}` and no row gives the lying reason for it"
            ));
        }
    }
    for kind in &excluded {
        let by_row = causes.iter().any(|row| {
            matches!(row.device, Device::Excluded(named) if named == kind)
                && matches!(row.account, Account::NotDrawn { .. })
        });
        if !by_row {
            return Err(format!(
                "{kind} lies outside the fault contract and no row marked not drawn names it"
            ));
        }
    }
    Ok(())
}

#[test]
fn every_device_fault_kind_is_drawn_documented_or_excluded() {
    if let Err(failure) = link(&CAUSES, &DOCUMENTED, SIM) {
        panic!("{failure}");
    }
}

fn naming_other_than(kind: Device) -> Vec<Cause> {
    CAUSES
        .into_iter()
        .filter(|row| row.device != kind)
        .collect()
}

#[test]
fn an_unaccounted_device_fault_kind_fails_the_link_guard() {
    let Kinds { table, excluded } = fault_kinds(SIM).expect("the committed documentation parses");
    assert_eq!(table.len(), 15, "{table:?}");
    assert_eq!(
        excluded,
        [
            "Volatile-cache loss",
            "timeout callbacks",
            "queue-pair failures"
        ]
    );
    let guard = |causes: &[Cause], source: &str| link(causes, &DOCUMENTED, source);
    assert_eq!(
        guard(&naming_other_than(Device::Table("Gray delay")), SIM),
        Err("Gray delay is named by no row".to_owned())
    );
    assert_eq!(
        guard(&naming_other_than(Device::Excluded("queue-pair failures")), SIM),
        Err("queue-pair failures lies outside the fault contract and no row marked not drawn names it".to_owned())
    );
    assert_eq!(
        guard(&naming_other_than(Device::Excluded("timeout callbacks")), SIM),
        Err("timeout callbacks lies outside the fault contract and no row marked not drawn names it".to_owned())
    );
    let short = naming_other_than(Device::Table("Short count"));
    assert_eq!(guard(&short, SIM), Ok(()));
    let unlinked: Vec<(&str, &str)> = DOCUMENTED
        .into_iter()
        .filter(|&(kind, _)| kind != "Short count")
        .collect();
    assert_eq!(
        link(&short, &unlinked, SIM),
        Err("Short count is named by no row".to_owned())
    );
    let mut stray = CAUSES.to_vec();
    stray.push(Cause {
        kind: "write protect",
        device: Device::Table("Write protect"),
        ..CAUSES[0]
    });
    assert_eq!(
        guard(&stray, SIM),
        Err(
            "write protect: Write protect is no kind the device module documentation names"
                .to_owned()
        )
    );
    let mut stray = CAUSES.to_vec();
    stray.push(Cause {
        kind: "power loss",
        device: Device::Excluded("power loss"),
        ..CAUSES[0]
    });
    assert_eq!(
        guard(&stray, SIM),
        Err("power loss: power loss is no kind the device module documentation names".to_owned())
    );
    // A row names a fault table kind as `Table` and a kind of the
    // exclusion sentence as `Excluded`, and neither the other way.
    let crossed = |kind: &'static str, device: Device| {
        let mut crossed = CAUSES.to_vec();
        crossed.push(Cause {
            kind,
            device,
            ..CAUSES[0]
        });
        guard(&crossed, SIM)
    };
    assert_eq!(
        crossed("slow command", Device::Excluded("Gray delay")),
        Err("slow command: Gray delay is no kind the device module documentation names".to_owned())
    );
    assert_eq!(
        crossed("timeout", Device::Table("timeout callbacks")),
        Err(
            "timeout: timeout callbacks is no kind the device module documentation names"
                .to_owned()
        )
    );
    let mut drawn = CAUSES.to_vec();
    for row in &mut drawn {
        if row.device == Device::Excluded("queue-pair failures") {
            row.account = CAUSES[0].account;
        }
    }
    assert!(matches!(CAUSES[0].account, Account::Drawn { .. }));
    assert_eq!(
        guard(&drawn, SIM),
        Err("queue-pair failures lies outside the fault contract and no row marked not drawn names it".to_owned())
    );
    assert_eq!(
        link(&CAUSES, &[("Write protect", "short-transfer")], SIM),
        Err(
            "short-transfer: Write protect is no kind the device module documentation names"
                .to_owned()
        )
    );
    assert_eq!(
        link(&CAUSES, &[("Short count", "short-count")], SIM),
        Err("Short count: short-count is no row of the differences table".to_owned())
    );
    let renamed = SIM.replacen("//! | Gray delay |", "//! | Slow command |", 1);
    assert_eq!(
        guard(&CAUSES, &renamed),
        Err("gray delay: Gray delay is no kind the device module documentation names".to_owned())
    );
    let narrowed = SIM.replacen("timeout callbacks and queue-pair", "queue-pair", 1);
    assert_eq!(
        guard(&CAUSES, &narrowed),
        Err(
            "timeout callbacks: timeout callbacks is no kind the device module documentation names"
                .to_owned()
        )
    );
    let wrapped = SIM.replacen(
        "callbacks and queue-pair",
        "callbacks and\n//! queue-pair",
        1,
    );
    assert_ne!(wrapped, SIM);
    assert_eq!(guard(&CAUSES, &wrapped), Ok(()));
    let widened = SIM.replacen(
        "Volatile-cache loss, timeout",
        "Volatile-cache loss, write\n//! protect, timeout",
        1,
    );
    assert_eq!(
        guard(&CAUSES, &widened),
        Err(
            "write protect lies outside the fault contract and no row marked not drawn names it"
                .to_owned()
        )
    );
    assert_eq!(
        guard(&CAUSES, "//! A device."),
        Err("the device module documentation holds no fault table".to_owned())
    );
    let unseparated = SIM.replacen("//! | --- | --- | --- |\n", "", 1);
    assert_eq!(
        guard(&CAUSES, &unseparated),
        Err("the fault table has no separator under its header".to_owned())
    );
    let compact = SIM.replacen(
        "//! | Gray delay |",
        "//! |Write protect|none|Honest|\n//! | Gray delay |",
        1,
    );
    assert_eq!(
        guard(&CAUSES, &compact),
        Err("the fault table row `|Write protect|none|Honest|` has another form than `| Kind | Symbol | Tag |`".to_owned())
    );
    let apart = SIM.replacen(
        "//!\n//! A device built by",
        "//!\n//! | Write protect | none | Honest |\n//! A device built by",
        1,
    );
    assert_ne!(apart, SIM);
    assert_eq!(
        guard(&CAUSES, &apart),
        Err(
            "`| Write protect | none | Honest |` is a table line apart from the fault table"
                .to_owned()
        )
    );
    let twice = SIM.replacen(OUTSIDE, &format!("{OUTSIDE} Power loss{OUTSIDE}"), 1);
    assert_eq!(
        guard(&CAUSES, &twice),
        Err("the device module documentation holds two exclusion sentences".to_owned())
    );
    let rowless = format!(
        "//! {}\n//! {}\n//!\n//! Power loss{OUTSIDE}",
        HEADER[0], HEADER[1]
    );
    assert_eq!(
        guard(&CAUSES, &rowless),
        Err("the fault table holds no row".to_owned())
    );
    // The Tag cells: a drawn kind is tagged honest, and a kind's tag
    // mentions lying exactly when a row gives the lying reason for it.
    let mut corrupt = CAUSES.to_vec();
    for row in &mut corrupt {
        if row.kind == "corrupt success" {
            row.account = CAUSES[0].account;
        }
    }
    assert_eq!(
        guard(&corrupt, SIM),
        Err("corrupt success is marked drawn and the fault table tags Corrupt success; misdirected read or write `Lying`".to_owned())
    );
    let retagged = |row: &str, tagged: &str| {
        let other = SIM.replacen(row, tagged, 1);
        assert_ne!(other, SIM);
        guard(&CAUSES, &other)
    };
    assert_eq!(
        retagged(
            "[`Fault::TornWrite`] | Honest |",
            "[`Fault::TornWrite`] | Lying |"
        ),
        Err("torn write is marked drawn and the fault table tags Torn write `Lying`".to_owned())
    );
    assert_eq!(
        retagged(
            "[`SimControl::try_delay`] | Honest |",
            "[`SimControl::try_delay`] | Lying |"
        ),
        Err(
            "the fault table tags Gray delay `Lying` and no row gives the lying reason for it"
                .to_owned()
        )
    );
    assert_eq!(
        retagged(
            "[`SimControl::try_damage`] | Lying |",
            "[`SimControl::try_damage`] | Honest |"
        ),
        Err("sector damage at rest gives the lying reason and the fault table tags Sector damage at rest `Honest`".to_owned())
    );
    // A row using `LYING` must name a fault table kind whose tag mentions
    // lying.
    let untagged = |kind: &str| {
        let mut causes = CAUSES.to_vec();
        let row = causes
            .iter_mut()
            .find(|row| row.kind == kind)
            .expect("the committed table names the kind");
        let Account::NotDrawn { source, .. } = row.account else {
            panic!("{kind} is marked drawn");
        };
        row.account = Account::NotDrawn {
            reason: LYING,
            source,
        };
        guard(&causes, SIM)
    };
    assert_eq!(
        untagged("volatile-cache loss"),
        Err("volatile-cache loss gives the lying reason and names no fault table kind".to_owned())
    );
    assert_eq!(
        untagged("loss burst"),
        Err("loss burst gives the lying reason and names no fault table kind".to_owned())
    );
    let unexcluded = SIM.replacen(OUTSIDE, ".", 1);
    assert_eq!(
        guard(&CAUSES, &unexcluded),
        Err("the device module documentation excludes no kind from the fault contract".to_owned())
    );
}
