//! A walk while a process moves a descriptor to a new number, as
//! `dup2(9, 12); close(9)` does.
//!
//! The process holds the node at every instant: the old descriptor until
//! the `dup2` returns, then the new one. `Host::check_unused` refuses a
//! namespace open in any process, and asks the walk alone for open
//! descriptors.

use std::ffi::{CStr, CString};
use std::io;
use std::sync::Mutex;

use super::{Facts, Node, Os, Queue, SHARE, Status, TASK_LINKS, Walker, answer};

const PID: u32 = 1 << 23;
const HELD: Node = Node::Device {
    block: true,
    major: 259,
    minor: 7,
};
const OTHER: Node = Node::Device {
    block: true,
    major: 259,
    minor: 8,
};

/// When the process moves the descriptor that holds [`HELD`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Move {
    Never,
    /// Once, to `to`, when the walk first reads the descriptor: after the
    /// listing that returned its number and before its read.
    OnRead {
        to: u32,
    },
    /// Once, from `from` to `to`, during the first listing, which has
    /// passed `to` and not reached `from`, so it returns neither.
    InListing {
        from: u32,
        to: u32,
    },
    /// To the next number, each time the walk reads the descriptor.
    OnEveryRead,
    /// To the other of the numbers `a` and `b`, each time the walk reads
    /// the descriptor.
    Between {
        a: u32,
        b: u32,
    },
    /// Once, to `to`, when the walk first reads the descriptor, and the
    /// process then opens [`OTHER`] at the old number, as an `open` that
    /// takes the lowest free number does.
    OnReadThenReopened {
        to: u32,
    },
}

/// One single-threaded process whose table holds [`OTHER`] at each of
/// `others` and [`HELD`] at one more descriptor, which the process moves as
/// `moves` says. The table holds [`HELD`] at every instant. A move to one of
/// `others` replaces that descriptor, as `dup2` onto an open number does.
struct Moving {
    moves: Move,
    others: Vec<u32>,
    reopened: Mutex<Option<u32>>,
    held: Mutex<u32>,
    moved: Mutex<u32>,
    listings: Mutex<u32>,
}

impl Moving {
    /// The walk's answer for a table holding [`HELD`] at `held`, with one
    /// walker, and the number that holds [`HELD`] once the walk ends.
    fn walk(others: Vec<u32>, held: u32, moves: Move) -> (Option<Vec<Node>>, u32) {
        let os = Self {
            moves,
            others,
            reopened: Mutex::new(None),
            held: Mutex::new(held),
            moved: Mutex::new(0),
            listings: Mutex::new(0),
        };
        let facts = Facts {
            reports_count: true,
            kcmp: false,
            begun: None,
            walkers: 1,
        };
        let queue = Queue::<String>::default();
        let found = Mutex::new(Some(Vec::new()));
        let listed = queue.list(&os, &String::new(), &mut Default::default());
        Walker::new(&os, &queue, &|node| node == HELD, facts).walk(&found);
        let answer = answer(found, listed);
        (answer, os.held.into_inner().unwrap())
    }

    fn move_to(&self, to: u32) {
        *self.held.lock().unwrap() = to;
        *self.moved.lock().unwrap() += 1;
    }
}

impl Os for Moving {
    type Table = String;

    fn status(&self, path: &CStr) -> io::Result<Status> {
        let path = path.to_str().unwrap();
        let size = if path.ends_with("/fd") {
            self.others.len() + 1
        } else {
            0
        };
        Ok(Status {
            size: size as libc::off_t,
            links: TASK_LINKS + 1,
        })
    }

    fn open(&self, path: &CStr) -> io::Result<String> {
        Ok(path.to_str().unwrap().to_owned())
    }

    fn entries(
        &self,
        table: &String,
        _: &mut [u8],
        mut visit: impl FnMut(&CStr),
    ) -> io::Result<()> {
        let mut names: Vec<u32> = if table.is_empty() || table.ends_with("/task") {
            vec![PID]
        } else {
            let mut listings = self.listings.lock().unwrap();
            *listings += 1;
            let mut names = self.others.clone();
            match self.moves {
                Move::InListing { from, to } if *listings == 1 => {
                    assert_eq!(*self.held.lock().unwrap(), from);
                    self.move_to(to);
                }
                _ => names.push(*self.held.lock().unwrap()),
            }
            names.extend(*self.reopened.lock().unwrap());
            names
        };
        names.sort_unstable();
        names.dedup();
        for name in names {
            visit(&CString::new(name.to_string()).unwrap());
        }
        Ok(())
    }

    fn node(&self, _: &String, name: &CStr) -> io::Result<Option<Node>> {
        let fd: u32 = name.to_str().unwrap().parse().unwrap();
        let held = *self.held.lock().unwrap();
        if fd != held {
            if self.others.contains(&fd) || *self.reopened.lock().unwrap() == Some(fd) {
                return Ok(Some(OTHER));
            }
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let moved = *self.moved.lock().unwrap();
        match self.moves {
            Move::OnRead { to } if moved == 0 => self.move_to(to),
            Move::OnEveryRead => self.move_to(held + 1),
            Move::Between { a, b } => self.move_to(if held == a { b } else { a }),
            Move::OnReadThenReopened { to } if moved == 0 => {
                self.move_to(to);
                *self.reopened.lock().unwrap() = Some(held);
                return Ok(Some(OTHER));
            }
            _ => return Ok(Some(HELD)),
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn shares_leader_table(&self, _: u32, _: u32) -> bool {
        true
    }

    fn started(&self, _: u32, _: u32) -> Option<u64> {
        None
    }

    fn last_task(&self) -> Option<u32> {
        Some(0)
    }
}

/// The unmoved table is reported, and so is the same table whose descriptor
/// moves to a new number after the listing returned the old one and before
/// the walk reads it: the node never closed.
#[test]
fn a_descriptor_moved_to_a_new_number_after_its_table_was_listed_is_reported() {
    assert_eq!(
        Moving::walk(vec![3], 9, Move::Never),
        (Some(vec![HELD]), 9),
        "premise: the walk reads descriptor 9"
    );
    assert_eq!(
        Moving::walk(vec![3], 9, Move::OnRead { to: 12 }),
        (Some(vec![HELD]), 12),
        "a node open through the whole walk, moved from descriptor 9 to 12, was not reported"
    );
}

/// A listing returns numbers in ascending order, so a descriptor moved from
/// a number the listing has not reached to one it has passed is in neither
/// that listing nor any read of it, and no read reports it vanished.
#[test]
fn a_descriptor_moved_behind_the_listing_is_reported() {
    let moves = Move::InListing { from: 200, to: 5 };
    assert_eq!(
        Moving::walk(vec![3, 7], 200, moves),
        (Some(vec![HELD]), 5),
        "a node open through the whole walk, moved from descriptor 200 to 5, was not reported"
    );
}

/// A table of more than one share: the last descriptor is queued, and its
/// reader holds none of the listing but its share. The descriptor moves
/// after every listing its lister made.
#[test]
fn a_descriptor_of_a_queued_share_moved_before_its_read_is_reported() {
    let others: Vec<u32> = (0..SHARE as u32).collect();
    let held = SHARE as u32;
    assert_eq!(
        Moving::walk(others.clone(), held, Move::Never),
        (Some(vec![HELD]), held),
        "premise: the walk reads the queued descriptor"
    );
    assert_eq!(
        Moving::walk(others, held, Move::OnRead { to: 500 }),
        (Some(vec![HELD]), 500),
        "a node open through the whole walk, moved out of a queued share, was not reported"
    );
}

/// A descriptor that moves at every read is never read, so the walk has no
/// answer: it fails instead of reporting the node unused.
#[test]
fn a_descriptor_that_moves_at_every_read_fails_the_walk() {
    let (answer, held) = Moving::walk(vec![3], 9, Move::OnEveryRead);
    assert!(held > 9, "premise: the descriptor moved when it was read");
    assert_eq!(
        answer, None,
        "a node open through the whole walk and never read left the walk an answer"
    );
}

/// A descriptor that moves between two numbers at every read is never read
/// either: each number reads as vanished again and again, and the walk
/// fails instead of reporting the node unused.
#[test]
fn a_descriptor_that_moves_between_two_numbers_at_every_read_fails_the_walk() {
    let (answer, held) = Moving::walk(vec![3], 9, Move::Between { a: 9, b: 12 });
    assert!(
        held == 9 || held == 12,
        "premise: the descriptor stayed on one of its two numbers"
    );
    assert_eq!(
        answer, None,
        "a node open through the whole walk and never read left the walk an answer"
    );
}

/// `dup2(9, 3); close(9)` with descriptor 3 open on another file: the walk
/// has read 3 before the move, so no listing returns a number it has not
/// read, and the node sits at a number whose earlier read saw the other file.
#[test]
fn a_descriptor_moved_onto_a_number_already_read_is_reported() {
    assert_eq!(
        Moving::walk(vec![3], 9, Move::Never),
        (Some(vec![HELD]), 9),
        "premise: the walk reads descriptor 9"
    );
    assert_eq!(
        Moving::walk(vec![3], 9, Move::OnRead { to: 3 }),
        (Some(vec![HELD]), 3),
        "a node open through the whole walk, moved from descriptor 9 onto 3, was not reported"
    );
}

/// The same move in a table of more than one share, where the walker that
/// reads the queued share lists the whole table again.
#[test]
fn a_descriptor_of_a_queued_share_moved_onto_a_number_already_read_is_reported() {
    let others: Vec<u32> = (0..SHARE as u32).collect();
    assert_eq!(
        Moving::walk(others, SHARE as u32, Move::OnRead { to: 3 }),
        (Some(vec![HELD]), 3),
        "a node open through the whole walk, moved out of a queued share onto 3, was not reported"
    );
}

/// `dup2(9, 12); close(9); open(other)`: the open takes the freed number,
/// so the read of 9 finds the other file and nothing vanished.
#[test]
fn a_descriptor_moved_to_a_new_number_whose_old_number_is_reopened_is_reported() {
    assert_eq!(
        Moving::walk(vec![3], 9, Move::OnReadThenReopened { to: 12 }),
        (Some(vec![HELD]), 12),
        "a node open through the whole walk, moved from descriptor 9 to 12, was not reported"
    );
}

/// The same move and reopen in a queued share, whose reader lists the table
/// again only when a descriptor of the share vanished.
#[test]
fn a_descriptor_of_a_queued_share_moved_and_its_old_number_reopened_is_reported() {
    let others: Vec<u32> = (0..SHARE as u32).collect();
    assert_eq!(
        Moving::walk(others, SHARE as u32, Move::OnReadThenReopened { to: 500 }),
        (Some(vec![HELD]), 500),
        "a node open through the whole walk, moved out of a queued share, was not reported"
    );
}

/// `dup2(9, 3); close(9); open(other)` with descriptors 0 to 8 open, so the
/// open takes 9: the walk has read 3 before the move, and the read of 9
/// finds the other file, so nothing vanished.
#[test]
fn a_descriptor_moved_onto_a_number_already_read_whose_old_number_is_reopened_is_reported() {
    let others: Vec<u32> = (0..9).collect();
    assert_eq!(
        Moving::walk(others, 9, Move::OnReadThenReopened { to: 3 }),
        (Some(vec![HELD]), 3),
        "a node open through the whole walk, moved from descriptor 9 onto 3, was not reported"
    );
}

/// The same in a queued share: descriptors 0 to 127 open, the node at 128.
#[test]
fn a_descriptor_of_a_queued_share_moved_onto_a_number_already_read_whose_old_number_is_reopened_is_reported()
 {
    let others: Vec<u32> = (0..SHARE as u32).collect();
    assert_eq!(
        Moving::walk(others, SHARE as u32, Move::OnReadThenReopened { to: 3 }),
        (Some(vec![HELD]), 3),
        "a node open through the whole walk, moved out of a queued share onto 3, was not reported"
    );
}
