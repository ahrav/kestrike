//! The media comparison a Crash turn's activation records: each held write's
//! submitted bytes and the media under its range before death, compared
//! block by block with the media after the dead queue is drained or reset.
//!
//! A block landed when it reads as the write's submitted bytes and stayed
//! when it reads as the media before death. The landing is ambiguous when
//! the submitted bytes equal the media before death, when it reads as
//! neither, or when a later write of the held set covers the block: the
//! Crash turn executes the held writes in acceptance order, so only the
//! last of them that covers a shared block is compared there.
//!
//! The in-memory write check also sees delivered writes: their submissions
//! remain in the capture after their tokens leave the outstanding set.

use crate::sim::cut::Child;
use crate::sim::ledger::Evidence;
use crate::storage::device::sim::{Capture, Captured};
use crate::storage::owner_fixture::SimControl;
use crate::storage::{CommandToken, DeviceRange, Operation};

/// The 512-byte block a landing word gives one bit.
pub(super) const BLOCK: usize = 512;

/// A write the device held at death: its token, its first device byte, the
/// bytes it would write whole and the media under its range before death.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Held {
    pub(super) token: CommandToken,
    pub(super) start: u64,
    pub(super) submitted: Vec<u8>,
    pub(super) before: Vec<u8>,
}

impl Held {
    fn blocks(&self) -> u64 {
        (self.submitted.len() / BLOCK) as u64
    }

    fn covers(&self, block: u64) -> bool {
        let first = self.start / BLOCK as u64;
        (first..first + self.blocks()).contains(&block)
    }
}

fn accepted_since(capture: &Capture, first: u64) -> impl Iterator<Item = DeviceRange> + '_ {
    capture.events.iter().filter_map(move |event| match *event {
        Captured::Submitted {
            operation: Operation::Write,
            device,
            ordinal,
            ..
        } if ordinal >= first => Some(device),
        _ => None,
    })
}

/// An incomplete capture, or the device range of the first write that lacks
/// a matching child at its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteGap {
    Overflow,
    Undeclared(DeviceRange),
}

fn matches_child(device: DeviceRange, child: &Child) -> bool {
    device.start() / BLOCK as u64 == child.lba
        && device.byte_len() / BLOCK as u32 == u32::from(child.blocks)
}

/// Inspects write submissions at or after `first`. A matching prefix of whole
/// children suffices. The count includes the first differing or extra write;
/// overflow anywhere in the capture returns zero inspected and `Overflow`.
pub(super) fn write_gap(
    capture: &Capture,
    first: u64,
    children: &[Child],
) -> (usize, Option<WriteGap>) {
    if capture.overflow {
        return (0, Some(WriteGap::Overflow));
    }
    let mut inspected = 0;
    for device in accepted_since(capture, first) {
        let child = children.get(inspected);
        inspected += 1;
        match child {
            Some(child) if matches_child(device, child) => (),
            _ => return (inspected, Some(WriteGap::Undeclared(device))),
        }
    }
    (inspected, None)
}

/// The writes `events` show accepted and not yet delivered, in acceptance
/// order, as tokens with their device ranges.
fn outstanding(events: &[Captured]) -> Vec<(CommandToken, DeviceRange)> {
    let mut held = Vec::new();
    for event in events {
        match *event {
            Captured::Submitted {
                token,
                operation: Operation::Write,
                device,
                ..
            } => held.push((token, device)),
            Captured::Submitted { .. } => {}
            Captured::Delivered { token, .. } => held.retain(|&(t, _)| t != token),
        }
    }
    held
}

pub(super) fn matching_outstanding(
    events: &[Captured],
    children: &[Child],
) -> Option<Vec<(CommandToken, DeviceRange)>> {
    let held = outstanding(events);
    (held.len() == children.len()
        && held
            .iter()
            .zip(children)
            .all(|(&(_, device), child)| matches_child(device, child)))
    .then_some(held)
}

/// The held writes' measured landing words, read from `control`'s media,
/// with [`Evidence::Ambiguous`] when a compared block is not attributed.
pub(super) fn observe(control: &SimControl, held: &[Held]) -> (Vec<u64>, Evidence) {
    let after: Vec<Vec<u8>> = held
        .iter()
        .map(|write| control.device(write.start as usize, write.submitted.len()))
        .collect();
    match measure(held, &after) {
        (landing, true) => (landing, Evidence::Attributed),
        (landing, false) => (landing, Evidence::Ambiguous),
    }
}

/// Each held write's measured landing word, one bit per block from its
/// first, and whether every compared block was attributed; `held` is in
/// execution order and `after` holds the media under each write's range
/// once the dead queue is disposed of.
pub(super) fn measure(held: &[Held], after: &[Vec<u8>]) -> (Vec<u64>, bool) {
    let mut attributed = true;
    let landing = held
        .iter()
        .zip(after)
        .enumerate()
        .map(|(at, (write, after))| {
            let mut word = 0;
            for unit in 0..write.blocks() as usize {
                let block = write.start / BLOCK as u64 + unit as u64;
                let bytes = unit * BLOCK..(unit + 1) * BLOCK;
                let (submitted, before, read) = (
                    &write.submitted[bytes.clone()],
                    &write.before[bytes.clone()],
                    &after[bytes],
                );
                let overwritten = held[at + 1..].iter().any(|later| later.covers(block));
                if submitted == before || overwritten {
                    attributed = false;
                } else if read == submitted {
                    word |= 1 << unit;
                } else if read != before {
                    attributed = false;
                }
            }
            word
        })
        .collect();
    (landing, attributed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(ordinal: u64, operation: Operation, device: DeviceRange) -> Captured {
        Captured::Submitted {
            token: CommandToken::from_raw(ordinal),
            operation,
            device,
            host: ordinal as usize * 16384,
            ordinal,
        }
    }

    fn deliver(ordinal: u64, device: DeviceRange) -> Captured {
        Captured::Delivered {
            token: CommandToken::from_raw(ordinal),
            status: crate::storage::DeviceStatus::Kernel(device.byte_len() as i32),
        }
    }

    fn write(token: u64, start: u64, submitted: u8, before: u8, blocks: usize) -> Held {
        Held {
            token: CommandToken::from_raw(token),
            start,
            submitted: vec![submitted; blocks * BLOCK],
            before: vec![before; blocks * BLOCK],
        }
    }

    /// A landed prefix reads as the submitted bytes and the rest as the old
    /// media: the word names the prefix and every block is attributed.
    #[test]
    fn a_torn_prefix_measures_as_its_sectors() {
        let held = [write(1, 0, 0xAA, 0x11, 4)];
        let mut after = vec![0x11; 4 * BLOCK];
        after[..2 * BLOCK].fill(0xAA);
        assert_eq!(measure(&held, &[after]), (vec![0b0011], true));
    }

    /// Submitted bytes equal to the old media, a block reading as neither,
    /// and a block a later-executed write covers each leave the landing
    /// ambiguous; the earlier writer of a shared block is not compared there
    /// while the later one is.
    #[test]
    fn equal_bytes_foreign_bytes_and_later_overwrites_are_ambiguous() {
        let same = [write(1, 0, 0x11, 0x11, 1)];
        assert!(!measure(&same, &[vec![0x11; BLOCK]]).1);
        let foreign = [write(1, 0, 0xAA, 0x11, 1)];
        assert!(!measure(&foreign, &[vec![0x77; BLOCK]]).1);
        let (first, second) = (
            write(1, 0, 0xAA, 0x11, 2),
            write(2, BLOCK as u64, 0xBB, 0x11, 2),
        );
        let media = [0xAA, 0xBB, 0xBB].map(|byte| vec![byte; BLOCK]).concat();
        let after = [media[..2 * BLOCK].to_vec(), media[BLOCK..].to_vec()];
        assert_eq!(measure(&[first, second], &after), (vec![0b01, 0b11], false));
    }

    #[test]
    fn delivered_writes_after_install_stay_in_the_check_and_overflow_fails_closed() {
        let device = DeviceRange::new(4096, 4096).unwrap();
        let mut capture = Capture {
            accepted: 3,
            overflow: false,
            events: vec![
                submit(0, Operation::Write, DeviceRange::new(8192, 4096).unwrap()),
                submit(1, Operation::Read, DeviceRange::new(0, 4096).unwrap()),
                submit(2, Operation::Write, device),
                deliver(2, device),
            ],
        };
        assert_eq!(
            write_gap(&capture, 1, &[]),
            (1, Some(WriteGap::Undeclared(device)))
        );
        assert_eq!(write_gap(&capture, 3, &[]), (0, None));
        capture.overflow = true;
        assert_eq!(write_gap(&capture, 1, &[]), (0, Some(WriteGap::Overflow)));
        assert_eq!(write_gap(&capture, 3, &[]), (0, Some(WriteGap::Overflow)));
    }

    #[test]
    fn a_reordered_or_shortened_write_reports_its_original_range() {
        let descriptor = crate::sim::recovery::Recovery::Kib16.descriptor();
        let children = &descriptor
            .points
            .iter()
            .find(|p| p.operation == 1)
            .unwrap()
            .after;
        let a = DeviceRange::new(128 * 512, 16 * 512).unwrap();
        let b = DeviceRange::new(144 * 512, 16 * 512).unwrap();
        let short_a = DeviceRange::new(a.start(), 8 * 512).unwrap();
        let short_b = DeviceRange::new(b.start(), 8 * 512).unwrap();
        let extra = DeviceRange::new(160 * 512, 8 * 512).unwrap();
        let long_b = DeviceRange::new(b.start(), 24 * 512).unwrap();
        let w = |at, range| submit(at, Operation::Write, range);
        for (label, events, expected, held_matches) in [
            ("matched", vec![w(0, a), w(1, b)], (2, None), true),
            ("matching prefix", vec![w(0, a)], (1, None), false),
            ("reordered", vec![w(0, b), w(1, a)], (1, Some(b)), false),
            (
                "short first",
                vec![w(0, short_a), w(1, b)],
                (1, Some(short_a)),
                false,
            ),
            (
                "short second",
                vec![w(0, a), w(1, short_b)],
                (2, Some(short_b)),
                false,
            ),
            (
                "long second",
                vec![w(0, a), w(1, long_b)],
                (2, Some(long_b)),
                false,
            ),
            (
                "delivered extra",
                vec![
                    w(0, a),
                    w(1, b),
                    submit(2, Operation::Read, a),
                    deliver(2, a),
                    w(3, extra),
                    deliver(3, extra),
                ],
                (3, Some(extra)),
                true,
            ),
        ] {
            let accepted = events
                .iter()
                .filter(|e| matches!(e, Captured::Submitted { .. }))
                .count() as u64;
            let capture = Capture {
                accepted,
                overflow: false,
                events,
            };
            assert_eq!(
                write_gap(&capture, 0, children),
                (expected.0, expected.1.map(WriteGap::Undeclared)),
                "{label}"
            );
            assert_eq!(
                matching_outstanding(&capture.events, children).is_some(),
                held_matches,
                "{label}"
            );
        }
    }

    /// Only writes the capture shows accepted and not delivered are held.
    #[test]
    fn delivered_and_read_commands_are_not_held() {
        let range = |token: u64| DeviceRange::new(4096 * token, 4096).unwrap();
        let events = [
            submit(0, Operation::Write, range(0)),
            submit(1, Operation::Read, range(1)),
            submit(2, Operation::Write, range(2)),
            deliver(0, range(0)),
        ];
        assert_eq!(
            outstanding(&events),
            [(
                CommandToken::from_raw(2),
                DeviceRange::new(8192, 4096).unwrap()
            )]
        );
    }
}
