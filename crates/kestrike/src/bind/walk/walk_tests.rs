//! The walk's descriptor reads below the procfs seam: a descriptor the walk
//! cannot identify fails the walk.

use std::ffi::CStr;
use std::io;

use super::{Facts, Node, Os, Queue, Status, Walker};

/// A descriptor table whose descriptor `n` answers `statx` with record `n`.
struct Records(Vec<libc::statx>);

impl Os for Records {
    type Table = ();

    fn status(&self, _: &CStr) -> io::Result<Status> {
        unreachable!("a descriptor read reads no status")
    }

    fn open(&self, _: &CStr) -> io::Result<()> {
        unreachable!("a descriptor read opens no table")
    }

    fn entries(&self, _: &(), _: &mut [u8], _: impl FnMut(&CStr)) -> io::Result<()> {
        unreachable!("a descriptor read lists no table")
    }

    fn node(&self, _: &(), name: &CStr) -> io::Result<Option<Node>> {
        let at: usize = name.to_str().unwrap().parse().unwrap();
        Node::of(&self.0[at])
    }

    fn shares_leader_table(&self, _: u32, _: u32) -> bool {
        unreachable!("a descriptor read compares no tables")
    }

    fn started(&self, _: u32, _: u32) -> Option<u64> {
        unreachable!("a descriptor read reads no start time")
    }

    fn last_task(&self) -> Option<u32> {
        Some(0)
    }
}

/// A `statx` record that reports the fields in `mask` for a file of type
/// `kind` with device number `major:minor`.
fn statx_record(mask: u32, kind: libc::mode_t, (major, minor): (u32, u32)) -> libc::statx {
    // SAFETY: `statx` holds integers alone, and zero is a value of each.
    let mut record: libc::statx = unsafe { std::mem::zeroed() };
    record.stx_mask = mask;
    record.stx_mode = u16::try_from(kind).unwrap();
    record.stx_rdev_major = major;
    record.stx_rdev_minor = minor;
    record
}

/// The walk fails when it cannot identify a descriptor. A descriptor whose
/// `statx` record withholds the file's type may be the device the walk
/// looks for, so reading it fails the walk. A record that states a block
/// device's type is kept by its device number, and one that states a
/// regular file's type and withholds its inode is passed over, since the
/// file is known to be no device.
#[test]
fn a_descriptor_whose_file_type_is_withheld_fails_the_walk() {
    let device = Node::Device {
        block: true,
        major: 259,
        minor: 3,
    };
    let read = |record: libc::statx| {
        let os = Records(vec![record]);
        let queue = Queue::<()>::default();
        let matches = |node: Node| node == device;
        let facts = Facts {
            reports_count: true,
            kcmp: true,
            begun: None,
            walkers: 1,
        };
        let mut walker = Walker::new(&os, &queue, &matches, facts);
        walker.read(&(), c"0");
        (walker.found.clone(), walker.failed)
    };
    assert_eq!(
        read(statx_record(libc::STATX_TYPE, libc::S_IFBLK, (259, 3))),
        (vec![device], false),
        "premise: a block device's descriptor is found"
    );
    assert_eq!(
        read(statx_record(libc::STATX_TYPE, libc::S_IFREG, (0, 0))),
        (vec![], false),
        "premise: a regular file of unknown inode is passed over"
    );
    assert_eq!(
        read(statx_record(0, libc::S_IFBLK, (259, 3))),
        (vec![], true),
        "a descriptor of unknown type was passed over"
    );
}
