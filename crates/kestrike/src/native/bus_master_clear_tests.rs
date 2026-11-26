//! A stop that cannot clear the function's bus-master enable loses the port.
//!
//! A stop clears the function's bus-master enable and confirms it on read-back before the driver stops and
//! frees its queues. A stop that cannot clear it asks the supervisor to contain the host and keeps the
//! device lease, so the arena stays registered and held.
//!
//! The tests run over a leased detached `EnaPort` whose scripted driver stop would return 0. One fault:
//! the PCI function refuses the bus-master clear, in each of the three ways `Function::set_bus_master`
//! can refuse it. The command register reads all zeroes before the write; the clear writes all zeroes, so
//! its read-back proves nothing; or the device sets the bit again between the write and the read-back.
//! The stop must return `Err(Unproven)` without calling the driver stop, ask for containment once, grant
//! no proof, keep the lease and leave the registration refusing its undo. A second stop must return
//! `Err(Unproven)` again and call neither the driver nor the supervisor. The control runs the same steps
//! on a function whose clear reads back: the driver stops once with bus mastering already off, the stop
//! is `Ok`, one proof takes the lease and the registration is undone.
//!
//! Each test computes its observations into plain values, drops its fixtures, and only then asserts.

use std::cell::RefCell;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::rc::Rc;
use std::sync::Arc;

use super::burst::{Port, Unproven};
use super::ena::EnaPort;
use super::env::Environment;
use super::pci::Function;
use super::pci_tests::Dir;
use super::registration_tests::{Recorder, new_arena, ready, watchdog};

/// Memory decoding, bus-master enable and interrupt disable: a live function that can reach memory.
const LIVE: u16 = 0x0406;

/// Bus-master enable in the command register.
const BUS_MASTER: u16 = 0x0004;

/// Offset of the command register in the configuration space.
const COMMAND: u64 = 4;

/// How the function answers the stop's bus-master clear.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// The clear is written and reads back clear.
    Clears,
    /// The command register reads all zeroes before the write.
    ReadsZero,
    /// Bus-master enable is the register's only bit, so the clear writes all zeroes and its read-back
    /// is the all-zero read that proves nothing.
    ClearsToZero,
    /// The bit is set again after the write and before the read-back.
    SetsItAgain,
}

/// What two stops in a row showed, as a value that outlives the fixtures.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// The two stops' results.
    stops: [Result<(), Unproven>; 2],
    /// The command register each driver-stop call read.
    driver: Vec<Option<u16>>,
    /// Containment requests after the first stop and after the second.
    contained: [u32; 2],
    /// Whether the port gave a stop proof, and whether it gave a second one.
    proofs: [bool; 2],
    /// Whether the port still holds its device lease after the proof was asked for.
    leased: bool,
    /// Whether the registration took the proof, `None` when there was none to give it.
    returned: Option<bool>,
    /// Whether the registration's undo went through.
    undone: bool,
}

/// What the property requires of a stop whose clear the function refuses.
fn lost() -> Seen {
    Seen {
        stops: [Err(Unproven), Err(Unproven)],
        driver: Vec::new(),
        contained: [1, 1],
        proofs: [false, false],
        leased: true,
        returned: None,
        undone: false,
    }
}

/// What the property requires of a stop whose clear reads back and whose driver returns 0: the driver
/// runs once, with bus mastering already off.
fn stopped() -> Seen {
    Seen {
        stops: [Ok(()), Ok(())],
        driver: vec![Some(LIVE & !BUS_MASTER)],
        contained: [0, 0],
        proofs: [true, false],
        leased: false,
        returned: Some(true),
        undone: true,
    }
}

/// Stops a configured, leased port twice over a function that answers the clear as `function` says,
/// with a driver stop that returns 0, then asks for the proof and the registration's undo.
fn stop_twice(function: Answer) -> Seen {
    let (env, arena) = (Environment::detached(), new_arena());
    let mut registration = ready(&env, &arena);
    let dir = Dir::new(
        match function {
            Answer::Clears | Answer::SetsItAgain => LIVE,
            Answer::ReadsZero => 0,
            Answer::ClearsToZero => BUS_MASTER,
        },
        None,
    );
    let supervisor = Arc::new(Recorder::new());
    let lease = registration.device_attached();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let driver = Rc::clone(&calls);
    let mut port = EnaPort::detached(
        Function::open(&dir.0).unwrap(),
        None,
        registration.id(),
        false,
        supervisor.clone(),
    )
    .leased(lease)
    .driver_stop(move |pci| {
        driver.borrow_mut().push(pci.command().ok());
        0
    });
    if matches!(function, Answer::SetsItAgain) {
        let config = OpenOptions::new()
            .write(true)
            .open(dir.0.join("config"))
            .unwrap();
        port.stall_before_proof(move || config.write_all_at(&LIVE.to_le_bytes(), COMMAND).unwrap());
    }
    let first = Port::stop(&mut port);
    let after_first = supervisor.requests();
    let second = Port::stop(&mut port);
    let after_second = supervisor.requests();
    let proof = port.stop_proof();
    let proofs = [proof.is_some(), port.stop_proof().is_some()];
    let leased = port.device_lease().is_some();
    let returned = proof.map(|proof| registration.device_stopped(proof).is_ok());
    let undone = registration.unregister(&watchdog()).is_ok();
    let driver = calls.borrow().clone();
    drop(port);
    Seen {
        stops: [first, second],
        driver,
        contained: [after_first, after_second],
        proofs,
        leased,
        returned,
        undone,
    }
}

#[test]
fn a_command_register_that_reads_zero_loses_the_port_before_the_driver_stops() {
    let seen = stop_twice(Answer::ReadsZero);
    assert_eq!(seen, lost());
}

#[test]
fn a_clear_that_writes_zero_proves_nothing_and_loses_the_port() {
    let seen = stop_twice(Answer::ClearsToZero);
    assert_eq!(seen, lost());
}

#[test]
fn a_clear_that_does_not_read_back_loses_the_port_before_the_driver_stops() {
    let seen = stop_twice(Answer::SetsItAgain);
    assert_eq!(seen, lost());
}

#[test]
fn a_clear_that_reads_back_stops_the_driver_and_grants_one_proof() {
    let seen = stop_twice(Answer::Clears);
    assert_eq!(seen, stopped());
}
