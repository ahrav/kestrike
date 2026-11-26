//! The mount record parser and the filesystem contract over literal
//! `/proc/self/mountinfo` lines and directory facts.

use super::Refusal;
use super::mount::{Mount, devname, journaled, owned, record, supported, umask};

const TABLE: &str = "\
22 1 259:1 / / rw,noatime shared:1 - xfs /dev/nvme0n1p1 rw,attr2,inode64,logbufs=8,noquota
40 22 7:0 / /mnt/ordered rw,relatime shared:20 - ext4 /dev/loop0 rw
43 22 7:3 / /mnt/read\\040only ro,relatime - xfs /dev/loop3 ro
44 22 0:30 / /dev/shm rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,inode64
45 22 7:4 / /mnt/old rw master:3 - ext3 /dev/loop4 rw,data=ordered
";

/// The record of each mount ID carries its own type and both option lists,
/// whatever optional fields precede the separator.
#[test]
fn a_mount_record_is_found_by_its_id() {
    assert_eq!(
        record(TABLE, 40),
        Some(Mount {
            device: "7:0",
            fstype: "ext4",
            mount_options: "rw,relatime",
            super_options: "rw"
        })
    );
    assert_eq!(
        record(TABLE, 43),
        Some(Mount {
            device: "7:3",
            fstype: "xfs",
            mount_options: "ro,relatime",
            super_options: "ro"
        })
    );
    assert_eq!(record(TABLE, 99), None);
}

/// Read-write ext4 and xfs records pass; a read-only mount and every other
/// filesystem type, ext3 included, are refused by name. The ext4 data mode
/// and barriers are judged on the device's option list instead.
#[test]
fn only_read_write_ext4_and_xfs_records_pass() {
    let verdict = |id| supported(&record(TABLE, id).expect("the table holds the mount"));
    assert_eq!(verdict(22), Ok(()));
    assert_eq!(verdict(40), Ok(()));
    assert_eq!(verdict(43), Err(Refusal::Mount("ro".into())));
    assert_eq!(verdict(44), Err(Refusal::Filesystem("tmpfs".into())));
    assert_eq!(verdict(45), Err(Refusal::Filesystem("ext3".into())));
    // `ro` in either option list alone refuses the mount.
    for (mount_options, super_options) in [("ro,relatime", "rw"), ("rw,relatime", "ro")] {
        let mount = Mount {
            device: "7:0",
            fstype: "xfs",
            mount_options,
            super_options,
        };
        assert_eq!(supported(&mount), Err(Refusal::Mount("ro".into())));
    }
}

/// The state directory must belong to the running user with exactly mode
/// 0700; a foreign owner, any group or other bit, and a set-ID or sticky
/// bit are refused.
#[test]
fn a_state_directory_is_the_users_own_with_mode_0700() {
    assert_eq!(owned(1000, 0o040_700, 1000), Ok(()));
    assert_eq!(owned(0, 0o040_700, 1000), Err(Refusal::Owner(0)));
    assert_eq!(owned(1000, 0o040_750, 1000), Err(Refusal::Mode(0o750)));
    assert_eq!(owned(1000, 0o040_500, 1000), Err(Refusal::Mode(0o500)));
    assert_eq!(owned(1000, 0o041_700, 1000), Err(Refusal::Mode(0o1700)));
}

/// A umask that clears no owner bit passes; one that clears any owner bit,
/// or a status text with no umask, is refused.
#[test]
fn the_umask_leaves_every_owner_bit() {
    assert_eq!(umask("Name:\tcampaign\nUmask:\t0022\nState:\tR\n"), Ok(()));
    assert_eq!(umask("Umask:\t0077\n"), Ok(()));
    assert_eq!(umask("Umask:\t0277\n"), Err(Refusal::Umask(Some(0o277))));
    assert_eq!(umask("Umask:\t0477\n"), Err(Refusal::Umask(Some(0o477))));
    assert_eq!(umask("Umask:\t0177\n"), Err(Refusal::Umask(Some(0o177))));
    assert_eq!(umask("Name:\tcampaign\n"), Err(Refusal::Umask(None)));
}

/// The ext4 option list decides what the mount record hides: ordered and
/// journal data pass, while a superblock default of writeback, a missing
/// journal (no data mode at all) and disabled barriers are refused. The
/// lists are abridged from the kernel's output on loop devices made with
/// `mkfs.ext4`, `tune2fs -o journal_data_writeback` and
/// `mkfs.ext4 -O ^has_journal`.
#[test]
fn the_ext4_option_list_requires_a_journal_in_ordered_or_journal_mode() {
    let ordered = "rw\nbsddf\njournal_checksum\nbarrier\nerrors=continue\ncommit=5\ndata=ordered\n";
    assert_eq!(journaled(ordered), Ok(()));
    assert_eq!(journaled("rw\nbarrier\ndata=journal\n"), Ok(()));
    assert_eq!(
        journaled("rw\nbarrier\ndata=writeback\n"),
        Err(Refusal::Mount("data=writeback".into()))
    );
    assert_eq!(
        journaled("rw\nbsddf\nbarrier\nerrors=continue\n"),
        Err(Refusal::Mount("no journal data mode".into()))
    );
    assert_eq!(
        journaled("rw\nnobarrier\ndata=ordered\n"),
        Err(Refusal::Mount("nobarrier".into()))
    );
    assert_eq!(
        devname("MAJOR=7\nMINOR=0\nDEVNAME=loop0\nDEVTYPE=disk\n"),
        Some("loop0")
    );
    assert_eq!(devname("MAJOR=7\nMINOR=0\n"), None);
    assert_eq!(devname("DEVNAME=../x\n"), None);
}
